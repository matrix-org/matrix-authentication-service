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

use chrono::{DateTime, Utc};
use mas_data_model::{AccessToken, RefreshToken, Session};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, DatabaseError, DatabaseInconsistencyError};

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        user_session.id = %session.user_session_id,
        client.id = %session.client_id,
        refresh_token.id,
    ),
    err,
)]
pub async fn add_refresh_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &Session,
    access_token: AccessToken,
    refresh_token: String,
) -> Result<RefreshToken, sqlx::Error> {
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
    .await?;

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
            SELECT rt.oauth2_refresh_token_id
                 , rt.refresh_token     AS oauth2_refresh_token
                 , rt.created_at        AS oauth2_refresh_token_created_at
                 , at.oauth2_access_token_id AS "oauth2_access_token_id?"
                 , at.access_token      AS "oauth2_access_token?"
                 , at.created_at        AS "oauth2_access_token_created_at?"
                 , at.expires_at        AS "oauth2_access_token_expires_at?"
                 , os.oauth2_session_id AS "oauth2_session_id!"
                 , os.oauth2_client_id  AS "oauth2_client_id!"
                 , os.scope             AS "oauth2_session_scope!"
                 , os.user_session_id   AS "user_session_id!"
            FROM oauth2_refresh_tokens rt
            INNER JOIN oauth2_sessions os
              USING (oauth2_session_id)
            LEFT JOIN oauth2_access_tokens at
              USING (oauth2_access_token_id)

            WHERE rt.refresh_token = $1
              AND rt.consumed_at IS NULL
              AND rt.revoked_at  IS NULL
              AND os.finished_at IS NULL
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
        _ => return Err(DatabaseInconsistencyError::on("oauth2_access_tokens").into()),
    };

    let refresh_token = RefreshToken {
        id: res.oauth2_refresh_token_id.into(),
        refresh_token: res.oauth2_refresh_token,
        created_at: res.oauth2_refresh_token_created_at,
        access_token,
    };

    let session_id = res.oauth2_session_id.into();
    let scope = res.oauth2_session_scope.parse().map_err(|e| {
        DatabaseInconsistencyError::on("oauth2_sessions")
            .column("scope")
            .row(session_id)
            .source(e)
    })?;

    let session = Session {
        id: session_id,
        client_id: res.oauth2_client_id.into(),
        user_session_id: res.user_session_id.into(),
        scope,
        finished_at: None,
    };

    Ok(Some((refresh_token, session)))
}

#[tracing::instrument(
    skip_all,
    fields(
        %refresh_token.id,
    ),
    err,
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
