// Copyright 2022 The Matrix.org Foundation C.I.C.
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
use argon2::{Argon2, PasswordHash};
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{CompatAccessToken, CompatSession, Device, User, UserEmail};
use sqlx::{Acquire, PgExecutor, Postgres};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};

use crate::{
    user::lookup_user_by_username, DatabaseInconsistencyError, IdAndCreationTime, PostgresqlBackend,
};

pub struct CompatAccessTokenLookup {
    compat_access_token_id: i64,
    compat_access_token: String,
    compat_access_token_expires_after: Option<i32>,
    compat_access_token_created_at: DateTime<Utc>,
    compat_session_id: i64,
    compat_session_created_at: DateTime<Utc>,
    compat_session_deleted_at: Option<DateTime<Utc>>,
    compat_session_device_id: String,
    user_id: i64,
    user_username: String,
    user_email_id: Option<i64>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
#[error("failed to lookup compat access token")]
pub enum CompatAccessTokenLookupError {
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl CompatAccessTokenLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Database(sqlx::Error::RowNotFound))
    }
}

#[tracing::instrument(skip(executor), err)]
pub async fn lookup_active_compat_access_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<
    (
        CompatAccessToken<PostgresqlBackend>,
        CompatSession<PostgresqlBackend>,
    ),
    CompatAccessTokenLookupError,
> {
    let res = sqlx::query_as!(
        CompatAccessTokenLookup,
        r#"
            SELECT
                ct.id              AS "compat_access_token_id",
                ct.token           AS "compat_access_token",
                ct.created_at      AS "compat_access_token_created_at",
                ct.expires_after   AS "compat_access_token_expires_after",
                cs.id              AS "compat_session_id",
                cs.created_at      AS "compat_session_created_at",
                cs.deleted_at      AS "compat_session_deleted_at",
                cs.device_id       AS "compat_session_device_id",
                 u.id              AS "user_id!",
                 u.username        AS "user_username!",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"

            FROM compat_access_tokens ct
            INNER JOIN compat_sessions cs
              ON cs.id = ct.compat_session_id
            INNER JOIN users u
              ON u.id = cs.user_id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id

            WHERE ct.token = $1
              AND cs.deleted_at IS NULL
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch compat access token"))
    .await?;

    let token = CompatAccessToken {
        data: res.compat_access_token_id,
        token: res.compat_access_token,
        created_at: res.compat_access_token_created_at,
        expires_after: res
            .compat_access_token_expires_after
            .map(|d| Duration::seconds(d.into())),
    };

    let primary_email = match (
        res.user_email_id,
        res.user_email,
        res.user_email_created_at,
        res.user_email_confirmed_at,
    ) {
        (Some(id), Some(email), Some(created_at), confirmed_at) => Some(UserEmail {
            data: id,
            email,
            created_at,
            confirmed_at,
        }),
        (None, None, None, None) => None,
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let user = User {
        data: res.user_id,
        username: res.user_username,
        sub: format!("fake-sub-{}", res.user_id),
        primary_email,
    };

    let device = Device::try_from(res.compat_session_device_id).unwrap();

    let session = CompatSession {
        data: res.compat_session_id,
        user,
        device,
        created_at: res.compat_session_created_at,
        deleted_at: res.compat_session_deleted_at,
    };

    Ok((token, session))
}

#[tracing::instrument(skip(conn, password, token), err)]
pub async fn compat_login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: &str,
    device: Device,
    token: String,
) -> Result<
    (
        CompatAccessToken<PostgresqlBackend>,
        CompatSession<PostgresqlBackend>,
    ),
    anyhow::Error,
> {
    let mut txn = conn.begin().await.context("could not start transaction")?;

    // First, lookup the user
    let user = lookup_user_by_username(&mut txn, username).await?;

    // Now, fetch the hashed password from the user associated with that session
    let hashed_password: String = sqlx::query_scalar!(
        r#"
            SELECT up.hashed_password
            FROM user_passwords up
            WHERE up.user_id = $1
            ORDER BY up.created_at DESC
            LIMIT 1
        "#,
        user.data,
    )
    .fetch_one(&mut txn)
    .instrument(tracing::info_span!("Lookup hashed password"))
    .await?;

    // TODO: pass verifiers list as parameter
    // Verify the password in a blocking thread to avoid blocking the async executor
    let password = password.to_string();
    task::spawn_blocking(move || {
        let context = Argon2::default();
        let hasher = PasswordHash::new(&hashed_password)?;
        hasher.verify_password(&[&context], &password)
    })
    .instrument(tracing::info_span!("Verify hashed password"))
    .await??;

    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
            INSERT INTO compat_sessions (user_id, device_id)
            VALUES ($1, $2)
            RETURNING id, created_at
        "#,
        user.data,
        device.as_str(),
    )
    .fetch_one(&mut txn)
    .instrument(tracing::info_span!("Insert compat session"))
    .await
    .context("could not insert compat session")?;

    let session = CompatSession {
        data: res.id,
        user,
        device,
        created_at: res.created_at,
        deleted_at: None,
    };

    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
            INSERT INTO compat_access_tokens (compat_session_id, token)
            VALUES ($1, $2)
            RETURNING id, created_at
        "#,
        session.data,
        token,
    )
    .fetch_one(&mut txn)
    .instrument(tracing::info_span!("Insert compat access token"))
    .await
    .context("could not insert compat access token")?;

    let token = CompatAccessToken {
        data: res.id,
        token,
        created_at: res.created_at,
        expires_after: None,
    };

    txn.commit().await.context("could not commit transaction")?;
    Ok((token, session))
}

#[tracing::instrument(skip_all, err)]
pub async fn compat_logout(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<(), anyhow::Error> {
    let res = sqlx::query!(
        r#"
            UPDATE compat_sessions
            SET deleted_at = NOW()
            FROM compat_access_tokens
            WHERE compat_access_tokens.token = $1
              AND compat_sessions.id = compat_access_tokens.id 
              AND compat_sessions.deleted_at IS NULL
        "#,
        token,
    )
    .execute(executor)
    .await
    .context("could not update compat access token")?;

    match res.rows_affected() {
        1 => Ok(()),
        0 => anyhow::bail!("no row affected"),
        _ => anyhow::bail!("too many row affected"),
    }
}
