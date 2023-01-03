// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, Authentication, BrowserSession, Session, User};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use uuid::Uuid;

use super::client::lookup_client;
use crate::{Clock, DatabaseError, DatabaseInconsistencyError};

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        client.id = %session.client.id,
        user.id = %session.browser_session.user.id,
        access_token.id,
    ),
    err,
)]
pub async fn add_access_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &Session,
    access_token: String,
    expires_after: Duration,
) -> Result<AccessToken, sqlx::Error> {
    let created_at = clock.now();
    let expires_at = created_at + expires_after;
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);

    tracing::Span::current().record("access_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_access_tokens
                (oauth2_access_token_id, oauth2_session_id, access_token, created_at, expires_at)
            VALUES
                ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        &access_token,
        created_at,
        expires_at,
    )
    .execute(executor)
    .await?;

    Ok(AccessToken {
        id,
        access_token,
        jti: id.to_string(),
        created_at,
        expires_at,
    })
}

#[derive(Debug)]
pub struct OAuth2AccessTokenLookup {
    oauth2_access_token_id: Uuid,
    oauth2_access_token: String,
    oauth2_access_token_created_at: DateTime<Utc>,
    oauth2_access_token_expires_at: DateTime<Utc>,
    oauth2_session_id: Uuid,
    oauth2_client_id: Uuid,
    scope: String,
    user_session_id: Uuid,
    user_session_created_at: DateTime<Utc>,
    user_id: Uuid,
    user_username: String,
    user_primary_user_email_id: Option<Uuid>,
    user_session_last_authentication_id: Option<Uuid>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_lines)]
pub async fn lookup_active_access_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<(AccessToken, Session)>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2AccessTokenLookup,
        r#"
            SELECT at.oauth2_access_token_id
                 , at.access_token      AS "oauth2_access_token"
                 , at.created_at        AS "oauth2_access_token_created_at"
                 , at.expires_at        AS "oauth2_access_token_expires_at"
                 , os.oauth2_session_id AS "oauth2_session_id!"
                 , os.oauth2_client_id  AS "oauth2_client_id!"
                 , os.scope             AS "scope!"
                 , us.user_session_id   AS "user_session_id!"
                 , us.created_at        AS "user_session_created_at!"
                 ,  u.user_id           AS "user_id!"
                 ,  u.username          AS "user_username!"
                 ,  u.primary_user_email_id AS "user_primary_user_email_id"
                 , usa.user_session_authentication_id AS "user_session_last_authentication_id?"
                 , usa.created_at       AS "user_session_last_authentication_created_at?"

            FROM oauth2_access_tokens at
            INNER JOIN oauth2_sessions os
              USING (oauth2_session_id)
            INNER JOIN user_sessions us
              USING (user_session_id)
            INNER JOIN users u
              USING (user_id)
            LEFT JOIN user_session_authentications usa
              USING (user_session_id)

            WHERE at.access_token = $1
              AND at.revoked_at IS NULL
              AND os.finished_at IS NULL

            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        token,
    )
    .fetch_one(&mut *conn)
    .await?;

    let access_token_id = Ulid::from(res.oauth2_access_token_id);
    let access_token = AccessToken {
        id: access_token_id,
        jti: access_token_id.to_string(),
        access_token: res.oauth2_access_token,
        created_at: res.oauth2_access_token_created_at,
        expires_at: res.oauth2_access_token_expires_at,
    };

    let session_id = res.oauth2_session_id.into();
    let client = lookup_client(&mut *conn, res.oauth2_client_id.into())
        .await?
        .ok_or_else(|| {
            DatabaseInconsistencyError::on("oauth2_sessions")
                .column("client_id")
                .row(session_id)
        })?;

    let user_id = Ulid::from(res.user_id);
    let user = User {
        id: user_id,
        username: res.user_username,
        sub: user_id.to_string(),
        primary_user_email_id: res.user_primary_user_email_id.map(Into::into),
    };

    let last_authentication = match (
        res.user_session_last_authentication_id,
        res.user_session_last_authentication_created_at,
    ) {
        (None, None) => None,
        (Some(id), Some(created_at)) => Some(Authentication {
            id: id.into(),
            created_at,
        }),
        _ => return Err(DatabaseInconsistencyError::on("user_session_authentications").into()),
    };

    let browser_session = BrowserSession {
        id: res.user_session_id.into(),
        created_at: res.user_session_created_at,
        finished_at: None,
        user,
        last_authentication,
    };

    let scope = res.scope.parse().map_err(|e| {
        DatabaseInconsistencyError::on("oauth2_sessions")
            .column("scope")
            .row(session_id)
            .source(e)
    })?;

    let session = Session {
        id: session_id,
        client,
        browser_session,
        scope,
    };

    Ok(Some((access_token, session)))
}

#[tracing::instrument(
    skip_all,
    fields(%access_token.id),
    err,
)]
pub async fn revoke_access_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    access_token: AccessToken,
) -> Result<(), DatabaseError> {
    let revoked_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_access_tokens
            SET revoked_at = $2
            WHERE oauth2_access_token_id = $1
        "#,
        Uuid::from(access_token.id),
        revoked_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}

pub async fn cleanup_expired(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
) -> Result<u64, sqlx::Error> {
    // Cleanup token which expired more than 15 minutes ago
    let threshold = clock.now() - Duration::minutes(15);
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_access_tokens
            WHERE expires_at < $1
        "#,
        threshold,
    )
    .execute(executor)
    .await?;

    Ok(res.rows_affected())
}
