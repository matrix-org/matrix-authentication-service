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

use anyhow::Context;
use chrono::{DateTime, Utc};
use mas_data_model::{
    AccessToken, Authentication, BrowserSession, RefreshToken, Session, User, UserEmail,
};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use uuid::Uuid;

use super::client::lookup_client;
use crate::{Clock, DatabaseError, DatabaseInconsistencyError2};

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        user.id = %session.browser_session.user.id,
        user_session.id = %session.browser_session.id,
        client.id = %session.client.id,
        refresh_token.id,
    ),
    err(Debug),
)]
pub async fn add_refresh_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &Session,
    access_token: AccessToken,
    refresh_token: String,
) -> anyhow::Result<RefreshToken> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("refresh_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_refresh_tokens
                (oauth2_refresh_token_id, oauth2_session_id, oauth2_access_token_id,
                 refresh_token, created_at)
            VALUES
                ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        Uuid::from(access_token.id),
        refresh_token,
        created_at,
    )
    .execute(executor)
    .await
    .context("could not insert oauth2 refresh token")?;

    Ok(RefreshToken {
        id,
        refresh_token,
        access_token: Some(access_token),
        created_at,
    })
}

struct OAuth2RefreshTokenLookup {
    oauth2_refresh_token_id: Uuid,
    oauth2_refresh_token: String,
    oauth2_refresh_token_created_at: DateTime<Utc>,
    oauth2_access_token_id: Option<Uuid>,
    oauth2_access_token: Option<String>,
    oauth2_access_token_created_at: Option<DateTime<Utc>>,
    oauth2_access_token_expires_at: Option<DateTime<Utc>>,
    oauth2_session_id: Uuid,
    oauth2_client_id: Uuid,
    oauth2_session_scope: String,
    user_session_id: Uuid,
    user_session_created_at: DateTime<Utc>,
    user_id: Uuid,
    user_username: String,
    user_session_last_authentication_id: Option<Uuid>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
    user_email_id: Option<Uuid>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::too_many_lines)]
pub async fn lookup_active_refresh_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<(RefreshToken, Session)>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2RefreshTokenLookup,
        r#"
            SELECT
                rt.oauth2_refresh_token_id,
                rt.refresh_token     AS oauth2_refresh_token,
                rt.created_at        AS oauth2_refresh_token_created_at,
                at.oauth2_access_token_id AS "oauth2_access_token_id?",
                at.access_token      AS "oauth2_access_token?",
                at.created_at        AS "oauth2_access_token_created_at?",
                at.expires_at        AS "oauth2_access_token_expires_at?",
                os.oauth2_session_id AS "oauth2_session_id!",
                os.oauth2_client_id  AS "oauth2_client_id!",
                os.scope             AS "oauth2_session_scope!",
                us.user_session_id   AS "user_session_id!",
                us.created_at        AS "user_session_created_at!",
                 u.user_id           AS "user_id!",
                 u.username          AS "user_username!",
                usa.user_session_authentication_id AS "user_session_last_authentication_id?",
                usa.created_at       AS "user_session_last_authentication_created_at?",
                ue.user_email_id     AS "user_email_id?",
                ue.email             AS "user_email?",
                ue.created_at        AS "user_email_created_at?",
                ue.confirmed_at      AS "user_email_confirmed_at?"
            FROM oauth2_refresh_tokens rt
            INNER JOIN oauth2_sessions os
              USING (oauth2_session_id)
            LEFT JOIN oauth2_access_tokens at
              USING (oauth2_access_token_id)
            INNER JOIN user_sessions us
              USING (user_session_id)
            INNER JOIN users u
              USING (user_id)
            LEFT JOIN user_session_authentications usa
              USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

            WHERE rt.refresh_token = $1
              AND rt.consumed_at IS NULL
              AND rt.revoked_at  IS NULL
              AND us.finished_at IS NULL
              AND os.finished_at IS NULL

            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        token,
    )
    .fetch_one(&mut *conn)
    .await?;

    let access_token = match (
        res.oauth2_access_token_id,
        res.oauth2_access_token,
        res.oauth2_access_token_created_at,
        res.oauth2_access_token_expires_at,
    ) {
        (None, None, None, None) => None,
        (Some(id), Some(access_token), Some(created_at), Some(expires_at)) => {
            let id = Ulid::from(id);
            Some(AccessToken {
                id,
                jti: id.to_string(),
                access_token,
                created_at,
                expires_at,
            })
        }
        _ => return Err(DatabaseInconsistencyError2::on("oauth2_access_tokens").into()),
    };

    let refresh_token = RefreshToken {
        id: res.oauth2_refresh_token_id.into(),
        refresh_token: res.oauth2_refresh_token,
        created_at: res.oauth2_refresh_token_created_at,
        access_token,
    };

    let session_id = res.oauth2_session_id.into();
    let client = lookup_client(&mut *conn, res.oauth2_client_id.into())
        .await?
        .ok_or_else(|| {
            DatabaseInconsistencyError2::on("oauth2_sessions")
                .column("client_id")
                .row(session_id)
        })?;

    let user_id = Ulid::from(res.user_id);
    let primary_email = match (
        res.user_email_id,
        res.user_email,
        res.user_email_created_at,
        res.user_email_confirmed_at,
    ) {
        (Some(id), Some(email), Some(created_at), confirmed_at) => Some(UserEmail {
            id: id.into(),
            email,
            created_at,
            confirmed_at,
        }),
        (None, None, None, None) => None,
        _ => {
            return Err(DatabaseInconsistencyError2::on("users")
                .column("primary_user_email_id")
                .row(user_id)
                .into())
        }
    };

    let user = User {
        id: user_id,
        username: res.user_username,
        sub: user_id.to_string(),
        primary_email,
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
        _ => return Err(DatabaseInconsistencyError2::on("user_session_authentications").into()),
    };

    let browser_session = BrowserSession {
        id: res.user_session_id.into(),
        created_at: res.user_session_created_at,
        user,
        last_authentication,
    };

    let scope = res.oauth2_session_scope.parse().map_err(|e| {
        DatabaseInconsistencyError2::on("oauth2_sessions")
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

    Ok(Some((refresh_token, session)))
}

#[tracing::instrument(
    skip_all,
    fields(
        %refresh_token.id,
    ),
    err(Debug),
)]
pub async fn consume_refresh_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    refresh_token: &RefreshToken,
) -> Result<(), DatabaseError> {
    let consumed_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_refresh_tokens
            SET consumed_at = $2
            WHERE oauth2_refresh_token_id = $1
        "#,
        Uuid::from(refresh_token.id),
        consumed_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}
