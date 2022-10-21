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
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, Authentication, BrowserSession, Session, User, UserEmail};
use sqlx::{Acquire, PgExecutor, Postgres};
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

use super::client::{lookup_client, ClientFetchError};
use crate::{DatabaseInconsistencyError, PostgresqlBackend};

#[tracing::instrument(
    skip_all, 
    fields(
        session.id = %session.data,
        client.id = %session.client.data,
        user.id = %session.browser_session.user.data,
        access_token.id,
    ),
    err(Debug),
)]
pub async fn add_access_token(
    executor: impl PgExecutor<'_>,
    session: &Session<PostgresqlBackend>,
    access_token: String,
    expires_after: Duration,
) -> anyhow::Result<AccessToken<PostgresqlBackend>> {
    let created_at = Utc::now();
    let expires_at = created_at + expires_after;
    let id = Ulid::from_datetime(created_at.into());

    tracing::Span::current().record("access_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_access_tokens
                (oauth2_access_token_id, oauth2_session_id, access_token, created_at, expires_at)
            VALUES
                ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.data),
        &access_token,
        created_at,
        expires_at,
    )
    .execute(executor)
    .await
    .context("could not insert oauth2 access token")?;

    Ok(AccessToken {
        data: id,
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
    user_session_last_authentication_id: Option<Uuid>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
    user_email_id: Option<Uuid>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
#[error("failed to lookup access token")]
pub enum AccessTokenLookupError {
    Database(#[from] sqlx::Error),
    ClientFetch(#[from] ClientFetchError),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl AccessTokenLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Database(sqlx::Error::RowNotFound))
    }
}

// TODO: remove that manual async
#[allow(clippy::too_many_lines, clippy::manual_async_fn)]
pub fn lookup_active_access_token<'a, 'c, A>(
    conn: A,
    token: &'a str,
) -> impl std::future::Future<
    Output = Result<
        (AccessToken<PostgresqlBackend>, Session<PostgresqlBackend>),
        AccessTokenLookupError,
    >,
> + Send
       + 'a
where
    A: Acquire<'c, Database = Postgres> + Send + 'a,
{
    async move {
        let mut conn = conn.acquire().await?;
        let res = sqlx::query_as!(
            OAuth2AccessTokenLookup,
            r#"
            SELECT
                at.oauth2_access_token_id,
                at.access_token    AS "oauth2_access_token",
                at.created_at      AS "oauth2_access_token_created_at",
                at.expires_at      AS "oauth2_access_token_expires_at",
                os.oauth2_session_id AS "oauth2_session_id!",
                os.oauth2_client_id AS "oauth2_client_id!",
                os.scope           AS "scope!",
                us.user_session_id AS "user_session_id!",
                us.created_at      AS "user_session_created_at!",
                 u.user_id AS "user_id!",
                 u.username        AS "user_username!",
                usa.user_session_authentication_id AS "user_session_last_authentication_id?",
                usa.created_at     AS "user_session_last_authentication_created_at?",
                ue.user_email_id AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"

            FROM oauth2_access_tokens at
            INNER JOIN oauth2_sessions os
              USING (oauth2_session_id)
            INNER JOIN user_sessions us
              USING (user_session_id)
            INNER JOIN users u
              USING (user_id)
            LEFT JOIN user_session_authentications usa
              USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

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

        let access_token = AccessToken {
            data: res.oauth2_access_token_id.into(),
            jti: res.oauth2_access_token_id.to_string(),
            access_token: res.oauth2_access_token,
            created_at: res.oauth2_access_token_created_at,
            expires_at: res.oauth2_access_token_expires_at,
        };

        let client = lookup_client(&mut *conn, res.oauth2_client_id.into()).await?;

        let primary_email = match (
            res.user_email_id,
            res.user_email,
            res.user_email_created_at,
            res.user_email_confirmed_at,
        ) {
            (Some(id), Some(email), Some(created_at), confirmed_at) => Some(UserEmail {
                data: id.into(),
                email,
                created_at,
                confirmed_at,
            }),
            (None, None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError.into()),
        };

        let id = Ulid::from(res.user_id);
        let user = User {
            data: id,
            username: res.user_username,
            sub: id.to_string(),
            primary_email,
        };

        let last_authentication = match (
            res.user_session_last_authentication_id,
            res.user_session_last_authentication_created_at,
        ) {
            (None, None) => None,
            (Some(id), Some(created_at)) => Some(Authentication {
                data: id.into(),
                created_at,
            }),
            _ => return Err(DatabaseInconsistencyError.into()),
        };

        let browser_session = BrowserSession {
            data: res.user_session_id.into(),
            created_at: res.user_session_created_at,
            user,
            last_authentication,
        };

        let scope = res.scope.parse().map_err(|_e| DatabaseInconsistencyError)?;

        let session = Session {
            data: res.oauth2_session_id.into(),
            client,
            browser_session,
            scope,
        };

        Ok((access_token, session))
    }
}

#[tracing::instrument(
    skip_all, 
    fields(access_token.id = %access_token.data),
    err(Debug),
)]
pub async fn revoke_access_token(
    executor: impl PgExecutor<'_>,
    access_token: AccessToken<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let revoked_at = Utc::now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_access_tokens
            SET revoked_at = $2
            WHERE oauth2_access_token_id = $1
        "#,
        Uuid::from(access_token.data),
        revoked_at,
    )
    .execute(executor)
    .await
    .context("could not revoke access tokens")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("no row were affected when revoking token"))
    }
}

pub async fn cleanup_expired(executor: impl PgExecutor<'_>) -> anyhow::Result<u64> {
    // Cleanup token which expired more than 15 minutes ago
    let threshold = Utc::now() - Duration::minutes(15);
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_access_tokens
            WHERE expires_at < $1 
        "#,
        threshold,
    )
    .execute(executor)
    .await
    .context("could not cleanup expired access tokens")?;

    Ok(res.rows_affected())
}
