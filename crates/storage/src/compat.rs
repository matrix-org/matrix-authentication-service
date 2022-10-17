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

use anyhow::{bail, Context};
use argon2::{Argon2, PasswordHash};
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{
    CompatAccessToken, CompatRefreshToken, CompatSession, CompatSsoLogin, CompatSsoLoginState,
    Device, User, UserEmail,
};
use sqlx::{postgres::types::PgInterval, Acquire, PgExecutor, Postgres};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use url::Url;

use crate::{
    user::lookup_user_by_username, DatabaseInconsistencyError, IdAndCreationTime, PostgresqlBackend,
};

struct CompatAccessTokenLookup {
    compat_access_token_id: i64,
    compat_access_token: String,
    compat_access_token_created_at: DateTime<Utc>,
    compat_access_token_expires_at: Option<DateTime<Utc>>,
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

#[tracing::instrument(skip_all, err)]
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
                ct.expires_at      AS "compat_access_token_expires_at",
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
              AND (ct.expires_at IS NULL OR ct.expires_at > NOW())
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
        expires_at: res.compat_access_token_expires_at,
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

pub struct CompatRefreshTokenLookup {
    compat_refresh_token_id: i64,
    compat_refresh_token: String,
    compat_refresh_token_created_at: DateTime<Utc>,
    compat_access_token_id: i64,
    compat_access_token: String,
    compat_access_token_created_at: DateTime<Utc>,
    compat_access_token_expires_at: Option<DateTime<Utc>>,
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
#[error("failed to lookup compat refresh token")]
pub enum CompatRefreshTokenLookupError {
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl CompatRefreshTokenLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Database(sqlx::Error::RowNotFound))
    }
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
pub async fn lookup_active_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<
    (
        CompatRefreshToken<PostgresqlBackend>,
        CompatAccessToken<PostgresqlBackend>,
        CompatSession<PostgresqlBackend>,
    ),
    CompatRefreshTokenLookupError,
> {
    let res = sqlx::query_as!(
        CompatRefreshTokenLookup,
        r#"
            SELECT
                cr.id              AS "compat_refresh_token_id",
                cr.token           AS "compat_refresh_token",
                cr.created_at      AS "compat_refresh_token_created_at",
                ct.id              AS "compat_access_token_id",
                ct.token           AS "compat_access_token",
                ct.created_at      AS "compat_access_token_created_at",
                ct.expires_at      AS "compat_access_token_expires_at",
                cs.id              AS "compat_session_id",
                cs.created_at      AS "compat_session_created_at",
                cs.deleted_at      AS "compat_session_deleted_at",
                cs.device_id       AS "compat_session_device_id",
                u.id               AS "user_id!",
                u.username         AS "user_username!",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"

            FROM compat_refresh_tokens cr
            INNER JOIN compat_access_tokens ct
              ON ct.id = cr.compat_access_token_id
            INNER JOIN compat_sessions cs
              ON cs.id = cr.compat_session_id
            INNER JOIN users u
              ON u.id = cs.user_id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id

            WHERE cr.token = $1
              AND cr.next_token_id IS NULL
              AND cs.deleted_at IS NULL
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch compat refresh token"))
    .await?;

    let refresh_token = CompatRefreshToken {
        data: res.compat_refresh_token_id,
        token: res.compat_refresh_token,
        created_at: res.compat_refresh_token_created_at,
    };

    let access_token = CompatAccessToken {
        data: res.compat_access_token_id,
        token: res.compat_access_token,
        created_at: res.compat_access_token_created_at,
        expires_at: res.compat_access_token_expires_at,
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

    Ok((refresh_token, access_token, session))
}

#[tracing::instrument(skip(conn, password), err)]
pub async fn compat_login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: &str,
    device: Device,
) -> Result<CompatSession<PostgresqlBackend>, anyhow::Error> {
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
    let password = password.to_owned();
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

    txn.commit().await.context("could not commit transaction")?;
    Ok(session)
}

#[tracing::instrument(skip(executor, token), err)]
pub async fn add_compat_access_token(
    executor: impl PgExecutor<'_>,
    session: &CompatSession<PostgresqlBackend>,
    token: String,
    expires_after: Option<Duration>,
) -> Result<CompatAccessToken<PostgresqlBackend>, anyhow::Error> {
    if let Some(expires_after) = expires_after {
        // For some reason, we need to convert the type first
        let pg_expires_after = PgInterval::try_from(expires_after)
            // For some reason, this error type does not let me to just bubble up the error here
            .map_err(|e| anyhow::anyhow!("failed to encode duration: {}", e))?;

        let res = sqlx::query_as!(
            IdAndCreationTime,
            r#"
                INSERT INTO compat_access_tokens (compat_session_id, token, created_at, expires_at)
                VALUES ($1, $2, NOW(), NOW() + $3)
                RETURNING id, created_at
            "#,
            session.data,
            token,
            pg_expires_after,
        )
        .fetch_one(executor)
        .instrument(tracing::info_span!("Insert compat access token"))
        .await
        .context("could not insert compat access token")?;

        Ok(CompatAccessToken {
            data: res.id,
            token,
            created_at: res.created_at,
            expires_at: Some(res.created_at + expires_after),
        })
    } else {
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
        .fetch_one(executor)
        .instrument(tracing::info_span!("Insert compat access token"))
        .await
        .context("could not insert compat access token")?;

        Ok(CompatAccessToken {
            data: res.id,
            token,
            created_at: res.created_at,
            expires_at: None,
        })
    }
}

pub async fn expire_compat_access_token(
    executor: impl PgExecutor<'_>,
    access_token: CompatAccessToken<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            UPDATE compat_access_tokens
            SET expires_at = NOW()
            WHERE id = $1
        "#,
        access_token.data,
    )
    .execute(executor)
    .await
    .context("failed to update compat access token")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no row were affected when updating access token"
        ))
    }
}

pub async fn add_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    session: &CompatSession<PostgresqlBackend>,
    access_token: &CompatAccessToken<PostgresqlBackend>,
    token: String,
) -> Result<CompatRefreshToken<PostgresqlBackend>, anyhow::Error> {
    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
            INSERT INTO compat_refresh_tokens (compat_session_id, compat_access_token_id, token)
            VALUES ($1, $2, $3)
            RETURNING id, created_at
        "#,
        session.data,
        access_token.data,
        token,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Insert compat refresh token"))
    .await
    .context("could not insert compat refresh token")?;

    Ok(CompatRefreshToken {
        data: res.id,
        token,
        created_at: res.created_at,
    })
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

pub async fn replace_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    refresh_token: &CompatRefreshToken<PostgresqlBackend>,
    next_refresh_token: &CompatRefreshToken<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            UPDATE compat_refresh_tokens
            SET next_token_id = $2
            WHERE id = $1
        "#,
        refresh_token.data,
        next_refresh_token.data
    )
    .execute(executor)
    .await
    .context("failed to update compat refresh token")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no row were affected when updating refresh token"
        ))
    }
}

pub async fn insert_compat_sso_login(
    executor: impl PgExecutor<'_>,
    token: String,
    redirect_uri: Url,
) -> anyhow::Result<CompatSsoLogin<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
        INSERT INTO compat_sso_logins (token, redirect_uri)
        VALUES ($1, $2)
        RETURNING id, created_at
        "#,
        &token,
        redirect_uri.as_str(),
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Insert compat SSO login"))
    .await
    .context("could not insert compat SSO login")?;

    Ok(CompatSsoLogin {
        data: res.id,
        token,
        redirect_uri,
        created_at: res.created_at,
        state: CompatSsoLoginState::Pending,
    })
}

struct CompatSsoLoginLookup {
    compat_sso_login_id: i64,
    compat_sso_login_token: String,
    compat_sso_login_redirect_uri: String,
    compat_sso_login_created_at: DateTime<Utc>,
    compat_sso_login_fullfilled_at: Option<DateTime<Utc>>,
    compat_sso_login_exchanged_at: Option<DateTime<Utc>>,
    compat_session_id: Option<i64>,
    compat_session_created_at: Option<DateTime<Utc>>,
    compat_session_deleted_at: Option<DateTime<Utc>>,
    compat_session_device_id: Option<String>,
    user_id: Option<i64>,
    user_username: Option<String>,
    user_email_id: Option<i64>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl TryFrom<CompatSsoLoginLookup> for CompatSsoLogin<PostgresqlBackend> {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: CompatSsoLoginLookup) -> Result<Self, Self::Error> {
        let redirect_uri = Url::parse(&res.compat_sso_login_redirect_uri)
            .map_err(|_| DatabaseInconsistencyError)?;

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
            _ => return Err(DatabaseInconsistencyError),
        };

        let user = match (res.user_id, res.user_username, primary_email) {
            (Some(id), Some(username), primary_email) => Some(User {
                data: id,
                username,
                sub: format!("fake-sub-{}", id),
                primary_email,
            }),
            (None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let session = match (
            res.compat_session_id,
            res.compat_session_device_id,
            res.compat_session_created_at,
            res.compat_session_deleted_at,
            user,
        ) {
            (Some(id), Some(device_id), Some(created_at), deleted_at, Some(user)) => {
                let device = Device::try_from(device_id).map_err(|_| DatabaseInconsistencyError)?;
                Some(CompatSession {
                    data: id,
                    user,
                    device,
                    created_at,
                    deleted_at,
                })
            }
            (None, None, None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let state = match (
            res.compat_sso_login_fullfilled_at,
            res.compat_sso_login_exchanged_at,
            session,
        ) {
            (None, None, None) => CompatSsoLoginState::Pending,
            (Some(fullfilled_at), None, Some(session)) => CompatSsoLoginState::Fullfilled {
                fullfilled_at,
                session,
            },
            (Some(fullfilled_at), Some(exchanged_at), Some(session)) => {
                CompatSsoLoginState::Exchanged {
                    fullfilled_at,
                    exchanged_at,
                    session,
                }
            }
            _ => return Err(DatabaseInconsistencyError),
        };

        Ok(CompatSsoLogin {
            data: res.compat_sso_login_id,
            token: res.compat_sso_login_token,
            redirect_uri,
            created_at: res.compat_sso_login_created_at,
            state,
        })
    }
}

#[derive(Debug, Error)]
#[error("failed to lookup compat SSO login")]
pub enum CompatSsoLoginLookupError {
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl CompatSsoLoginLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Database(sqlx::Error::RowNotFound))
    }
}

#[allow(clippy::too_many_lines)]
#[tracing::instrument(skip(executor), err)]
pub async fn get_compat_sso_login_by_id(
    executor: impl PgExecutor<'_>,
    id: i64,
) -> Result<CompatSsoLogin<PostgresqlBackend>, CompatSsoLoginLookupError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT
                cl.id              AS "compat_sso_login_id",
                cl.token           AS "compat_sso_login_token",
                cl.redirect_uri    AS "compat_sso_login_redirect_uri",
                cl.created_at      AS "compat_sso_login_created_at",
                cl.fullfilled_at   AS "compat_sso_login_fullfilled_at",
                cl.exchanged_at    AS "compat_sso_login_exchanged_at",
                cs.id              AS "compat_session_id?",
                cs.created_at      AS "compat_session_created_at?",
                cs.deleted_at      AS "compat_session_deleted_at?",
                cs.device_id       AS "compat_session_device_id?",
                u.id               AS "user_id?",
                u.username         AS "user_username?",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM compat_sso_logins cl
            LEFT JOIN compat_sessions cs
              ON cs.id = cl.compat_session_id
            LEFT JOIN users u
              ON u.id = cs.user_id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id
            WHERE cl.id = $1
        "#,
        id,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await?;

    Ok(res.try_into()?)
}

#[allow(clippy::too_many_lines)]
#[tracing::instrument(skip(executor), err)]
pub async fn get_compat_sso_login_by_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<CompatSsoLogin<PostgresqlBackend>, CompatSsoLoginLookupError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT
                cl.id              AS "compat_sso_login_id",
                cl.token           AS "compat_sso_login_token",
                cl.redirect_uri    AS "compat_sso_login_redirect_uri",
                cl.created_at      AS "compat_sso_login_created_at",
                cl.fullfilled_at   AS "compat_sso_login_fullfilled_at",
                cl.exchanged_at    AS "compat_sso_login_exchanged_at",
                cs.id              AS "compat_session_id?",
                cs.created_at      AS "compat_session_created_at?",
                cs.deleted_at      AS "compat_session_deleted_at?",
                cs.device_id       AS "compat_session_device_id?",
                u.id               AS "user_id?",
                u.username         AS "user_username?",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM compat_sso_logins cl
            LEFT JOIN compat_sessions cs
              ON cs.id = cl.compat_session_id
            LEFT JOIN users u
              ON u.id = cs.user_id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id
            WHERE cl.token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await?;

    Ok(res.try_into()?)
}

pub async fn fullfill_compat_sso_login(
    conn: impl Acquire<'_, Database = Postgres>,
    user: User<PostgresqlBackend>,
    mut login: CompatSsoLogin<PostgresqlBackend>,
    device: Device,
) -> anyhow::Result<CompatSsoLogin<PostgresqlBackend>> {
    if !matches!(login.state, CompatSsoLoginState::Pending) {
        bail!("sso login in wrong state");
    };

    let mut txn = conn.begin().await.context("could not start transaction")?;

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

    let res = sqlx::query_scalar!(
        r#"
            UPDATE compat_sso_logins
            SET
                fullfilled_at = NOW(),
                compat_session_id = $2
            WHERE
                id = $1
            RETURNING fullfilled_at AS "fullfilled_at!"
        "#,
        login.data,
        session.data,
    )
    .fetch_one(&mut txn)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await
    .context("could not update compat SSO login")?;

    let state = CompatSsoLoginState::Fullfilled {
        fullfilled_at: res,
        session,
    };

    login.state = state;

    txn.commit().await?;

    Ok(login)
}

pub async fn mark_compat_sso_login_as_exchanged(
    executor: impl PgExecutor<'_>,
    mut login: CompatSsoLogin<PostgresqlBackend>,
) -> anyhow::Result<CompatSsoLogin<PostgresqlBackend>> {
    let (fullfilled_at, session) = match login.state {
        CompatSsoLoginState::Fullfilled {
            fullfilled_at,
            session,
        } => (fullfilled_at, session),
        _ => bail!("sso login in wrong state"),
    };

    let res = sqlx::query_scalar!(
        r#"
            UPDATE compat_sso_logins
            SET
                exchanged_at = NOW()
            WHERE
                id = $1
            RETURNING exchanged_at AS "exchanged_at!"
        "#,
        login.data,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await
    .context("could not update compat SSO login")?;

    let state = CompatSsoLoginState::Exchanged {
        fullfilled_at,
        exchanged_at: res,
        session,
    };
    login.state = state;
    Ok(login)
}
