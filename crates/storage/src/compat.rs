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
use rand::Rng;
use sqlx::{Acquire, PgExecutor, Postgres, QueryBuilder};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    user::lookup_user_by_username,
    Clock, DatabaseInconsistencyError, PostgresqlBackend,
};

struct CompatAccessTokenLookup {
    compat_access_token_id: Uuid,
    compat_access_token: String,
    compat_access_token_created_at: DateTime<Utc>,
    compat_access_token_expires_at: Option<DateTime<Utc>>,
    compat_session_id: Uuid,
    compat_session_created_at: DateTime<Utc>,
    compat_session_finished_at: Option<DateTime<Utc>>,
    compat_session_device_id: String,
    user_id: Uuid,
    user_username: String,
    user_email_id: Option<Uuid>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
#[error("failed to lookup compat access token")]
pub enum CompatAccessTokenLookupError {
    Expired { when: DateTime<Utc> },
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl CompatAccessTokenLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(
            self,
            Self::Database(sqlx::Error::RowNotFound) | Self::Expired { .. }
        )
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn lookup_active_compat_access_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
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
                ct.compat_access_token_id,
                ct.access_token    AS "compat_access_token",
                ct.created_at      AS "compat_access_token_created_at",
                ct.expires_at      AS "compat_access_token_expires_at",
                cs.compat_session_id,
                cs.created_at      AS "compat_session_created_at",
                cs.finished_at     AS "compat_session_finished_at",
                cs.device_id       AS "compat_session_device_id",
                 u.user_id         AS "user_id!",
                 u.username        AS "user_username!",
                ue.user_email_id   AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"

            FROM compat_access_tokens ct
            INNER JOIN compat_sessions cs
              USING (compat_session_id)
            INNER JOIN users u
              USING (user_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

            WHERE ct.access_token = $1 AND cs.finished_at IS NULL
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch compat access token"))
    .await?;

    // Check for token expiration
    if let Some(expires_at) = res.compat_access_token_expires_at {
        if expires_at < clock.now() {
            return Err(CompatAccessTokenLookupError::Expired { when: expires_at });
        }
    }

    let token = CompatAccessToken {
        data: res.compat_access_token_id.into(),
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

    let device = Device::try_from(res.compat_session_device_id).unwrap();

    let session = CompatSession {
        data: res.compat_session_id.into(),
        user,
        device,
        created_at: res.compat_session_created_at,
        finished_at: res.compat_session_finished_at,
    };

    Ok((token, session))
}

pub struct CompatRefreshTokenLookup {
    compat_refresh_token_id: Uuid,
    compat_refresh_token: String,
    compat_refresh_token_created_at: DateTime<Utc>,
    compat_access_token_id: Uuid,
    compat_access_token: String,
    compat_access_token_created_at: DateTime<Utc>,
    compat_access_token_expires_at: Option<DateTime<Utc>>,
    compat_session_id: Uuid,
    compat_session_created_at: DateTime<Utc>,
    compat_session_finished_at: Option<DateTime<Utc>>,
    compat_session_device_id: String,
    user_id: Uuid,
    user_username: String,
    user_email_id: Option<Uuid>,
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
                cr.compat_refresh_token_id,
                cr.refresh_token   AS "compat_refresh_token",
                cr.created_at      AS "compat_refresh_token_created_at",
                ct.compat_access_token_id,
                ct.access_token    AS "compat_access_token",
                ct.created_at      AS "compat_access_token_created_at",
                ct.expires_at      AS "compat_access_token_expires_at",
                cs.compat_session_id,
                cs.created_at      AS "compat_session_created_at",
                cs.finished_at     AS "compat_session_finished_at",
                cs.device_id       AS "compat_session_device_id",
                u.user_id,
                u.username         AS "user_username!",
                ue.user_email_id   AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"

            FROM compat_refresh_tokens cr
            INNER JOIN compat_sessions cs
              USING (compat_session_id)
            INNER JOIN compat_access_tokens ct
              USING (compat_access_token_id)
            INNER JOIN users u
              USING (user_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

            WHERE cr.refresh_token = $1
              AND cr.consumed_at IS NULL
              AND cs.finished_at IS NULL
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch compat refresh token"))
    .await?;

    let refresh_token = CompatRefreshToken {
        data: res.compat_refresh_token_id.into(),
        token: res.compat_refresh_token,
        created_at: res.compat_refresh_token_created_at,
    };

    let access_token = CompatAccessToken {
        data: res.compat_access_token_id.into(),
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

    let device = Device::try_from(res.compat_session_device_id).unwrap();

    let session = CompatSession {
        data: res.compat_session_id.into(),
        user,
        device,
        created_at: res.compat_session_created_at,
        finished_at: res.compat_session_finished_at,
    };

    Ok((refresh_token, access_token, session))
}

#[tracing::instrument(
    skip_all,
    fields(
        user.username = username,
        user.id,
        compat_session.id,
        compat_session.device.id = device.as_str(),
    ),
    err(Display),
)]
pub async fn compat_login(
    conn: impl Acquire<'_, Database = Postgres> + Send,
    mut rng: impl Rng + Send,
    clock: &Clock,
    username: &str,
    password: &str,
    device: Device,
) -> Result<CompatSession<PostgresqlBackend>, anyhow::Error> {
    let mut txn = conn.begin().await.context("could not start transaction")?;

    // First, lookup the user
    let user = lookup_user_by_username(&mut txn, username).await?;
    tracing::Span::current().record("user.id", tracing::field::display(user.data));

    // Now, fetch the hashed password from the user associated with that session
    let hashed_password: String = sqlx::query_scalar!(
        r#"
            SELECT up.hashed_password
            FROM user_passwords up
            WHERE up.user_id = $1
            ORDER BY up.created_at DESC
            LIMIT 1
        "#,
        Uuid::from(user.data),
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

    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_session.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO compat_sessions
              (compat_session_id, user_id, device_id, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.data),
        device.as_str(),
        created_at,
    )
    .execute(&mut txn)
    .instrument(tracing::info_span!("Insert compat session"))
    .await
    .context("could not insert compat session")?;

    let session = CompatSession {
        data: id,
        user,
        device,
        created_at,
        finished_at: None,
    };

    txn.commit().await.context("could not commit transaction")?;
    Ok(session)
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_session.id = %session.data,
        compat_session.device.id = session.device.as_str(),
        compat_access_token.id,
        user.id = %session.user.data,
    ),
    err(Display),
)]
pub async fn add_compat_access_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &CompatSession<PostgresqlBackend>,
    token: String,
    expires_after: Option<Duration>,
) -> Result<CompatAccessToken<PostgresqlBackend>, anyhow::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_access_token.id", tracing::field::display(id));

    let expires_at = expires_after.map(|expires_after| created_at + expires_after);

    sqlx::query!(
        r#"
            INSERT INTO compat_access_tokens
                (compat_access_token_id, compat_session_id, access_token, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.data),
        token,
        created_at,
        expires_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat access token"))
    .await
    .context("could not insert compat access token")?;

    Ok(CompatAccessToken {
        data: id,
        token,
        created_at,
        expires_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_access_token.id = %access_token.data,
    ),
    err(Display),
)]
pub async fn expire_compat_access_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    access_token: CompatAccessToken<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    let expires_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE compat_access_tokens
            SET expires_at = $2
            WHERE compat_access_token_id = $1
        "#,
        Uuid::from(access_token.data),
        expires_at,
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

#[tracing::instrument(
    skip_all,
    fields(
        compat_session.id = %session.data,
        compat_session.device.id = session.device.as_str(),
        compat_access_token.id = %access_token.data,
        compat_refresh_token.id,
        user.id = %session.user.data,
    ),
    err(Display),
)]
pub async fn add_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &CompatSession<PostgresqlBackend>,
    access_token: &CompatAccessToken<PostgresqlBackend>,
    token: String,
) -> Result<CompatRefreshToken<PostgresqlBackend>, anyhow::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_refresh_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO compat_refresh_tokens
                (compat_refresh_token_id, compat_session_id,
                 compat_access_token_id, refresh_token, created_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.data),
        Uuid::from(access_token.data),
        token,
        created_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat refresh token"))
    .await
    .context("could not insert compat refresh token")?;

    Ok(CompatRefreshToken {
        data: id,
        token,
        created_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(compat_session.id),
    err(Display),
)]
pub async fn compat_logout(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    token: &str,
) -> Result<(), anyhow::Error> {
    let finished_at = clock.now();
    // TODO: this does not check for token expiration
    let compat_session_id = sqlx::query_scalar!(
        r#"
            UPDATE compat_sessions cs
            SET finished_at = $2
            FROM compat_access_tokens ca
            WHERE ca.access_token = $1
              AND ca.compat_session_id = cs.compat_session_id
              AND cs.finished_at IS NULL
            RETURNING cs.compat_session_id
        "#,
        token,
        finished_at,
    )
    .fetch_one(executor)
    .await
    .context("could not update compat access token")?;

    tracing::Span::current().record(
        "compat_session.id",
        tracing::field::display(compat_session_id),
    );

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_refresh_token.id = %refresh_token.data,
    ),
    err(Display),
)]
pub async fn consume_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    refresh_token: CompatRefreshToken<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    let consumed_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE compat_refresh_tokens
            SET consumed_at = $2
            WHERE compat_refresh_token_id = $1
        "#,
        Uuid::from(refresh_token.data),
        consumed_at,
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

#[tracing::instrument(
    skip_all,
    fields(
        compat_sso_login.id,
        compat_sso_login.redirect_uri = %redirect_uri,
    ),
    err(Display),
)]
pub async fn insert_compat_sso_login(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    login_token: String,
    redirect_uri: Url,
) -> Result<CompatSsoLogin<PostgresqlBackend>, anyhow::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_sso_login.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO compat_sso_logins
                (compat_sso_login_id, login_token, redirect_uri, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        &login_token,
        redirect_uri.as_str(),
        created_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat SSO login"))
    .await
    .context("could not insert compat SSO login")?;

    Ok(CompatSsoLogin {
        data: id,
        login_token,
        redirect_uri,
        created_at,
        state: CompatSsoLoginState::Pending,
    })
}

#[derive(sqlx::FromRow)]
struct CompatSsoLoginLookup {
    compat_sso_login_id: Uuid,
    compat_sso_login_token: String,
    compat_sso_login_redirect_uri: String,
    compat_sso_login_created_at: DateTime<Utc>,
    compat_sso_login_fulfilled_at: Option<DateTime<Utc>>,
    compat_sso_login_exchanged_at: Option<DateTime<Utc>>,
    compat_session_id: Option<Uuid>,
    compat_session_created_at: Option<DateTime<Utc>>,
    compat_session_finished_at: Option<DateTime<Utc>>,
    compat_session_device_id: Option<String>,
    user_id: Option<Uuid>,
    user_username: Option<String>,
    user_email_id: Option<Uuid>,
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
                data: id.into(),
                email,
                created_at,
                confirmed_at,
            }),
            (None, None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let user = match (res.user_id, res.user_username, primary_email) {
            (Some(id), Some(username), primary_email) => {
                let id = Ulid::from(id);
                Some(User {
                    data: id,
                    username,
                    sub: id.to_string(),
                    primary_email,
                })
            }

            (None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let session = match (
            res.compat_session_id,
            res.compat_session_device_id,
            res.compat_session_created_at,
            res.compat_session_finished_at,
            user,
        ) {
            (Some(id), Some(device_id), Some(created_at), finished_at, Some(user)) => {
                let device = Device::try_from(device_id).map_err(|_| DatabaseInconsistencyError)?;
                Some(CompatSession {
                    data: id.into(),
                    user,
                    device,
                    created_at,
                    finished_at,
                })
            }
            (None, None, None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let state = match (
            res.compat_sso_login_fulfilled_at,
            res.compat_sso_login_exchanged_at,
            session,
        ) {
            (None, None, None) => CompatSsoLoginState::Pending,
            (Some(fulfilled_at), None, Some(session)) => CompatSsoLoginState::Fulfilled {
                fulfilled_at,
                session,
            },
            (Some(fulfilled_at), Some(exchanged_at), Some(session)) => {
                CompatSsoLoginState::Exchanged {
                    fulfilled_at,
                    exchanged_at,
                    session,
                }
            }
            _ => return Err(DatabaseInconsistencyError),
        };

        Ok(CompatSsoLogin {
            data: res.compat_sso_login_id.into(),
            login_token: res.compat_sso_login_token,
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

#[tracing::instrument(
    skip_all,
    fields(
        compat_sso_login.id = %id,
    ),
    err,
)]
pub async fn get_compat_sso_login_by_id(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<CompatSsoLogin<PostgresqlBackend>, CompatSsoLoginLookupError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT
                cl.compat_sso_login_id,
                cl.login_token     AS "compat_sso_login_token",
                cl.redirect_uri    AS "compat_sso_login_redirect_uri",
                cl.created_at      AS "compat_sso_login_created_at",
                cl.fulfilled_at    AS "compat_sso_login_fulfilled_at",
                cl.exchanged_at    AS "compat_sso_login_exchanged_at",
                cs.compat_session_id AS "compat_session_id?",
                cs.created_at      AS "compat_session_created_at?",
                cs.finished_at     AS "compat_session_finished_at?",
                cs.device_id       AS "compat_session_device_id?",
                u.user_id          AS "user_id?",
                u.username         AS "user_username?",
                ue.user_email_id   AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM compat_sso_logins cl
            LEFT JOIN compat_sessions cs
              USING (compat_session_id)
            LEFT JOIN users u
              USING (user_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id
            WHERE cl.compat_sso_login_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await?;

    Ok(res.try_into()?)
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user.username = user.username,
    ),
    err(Display),
)]
pub async fn get_paginated_user_compat_sso_logins(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<CompatSsoLogin<PostgresqlBackend>>), anyhow::Error> {
    // TODO: this queries too much (like user info) which we probably don't need
    // because we already have them
    let mut query = QueryBuilder::new(
        r#"
            SELECT
                cl.compat_sso_login_id,
                cl.login_token     AS "compat_sso_login_token",
                cl.redirect_uri    AS "compat_sso_login_redirect_uri",
                cl.created_at      AS "compat_sso_login_created_at",
                cl.fulfilled_at    AS "compat_sso_login_fulfilled_at",
                cl.exchanged_at    AS "compat_sso_login_exchanged_at",
                cs.compat_session_id AS "compat_session_id",
                cs.created_at      AS "compat_session_created_at",
                cs.finished_at     AS "compat_session_finished_at",
                cs.device_id       AS "compat_session_device_id",
                u.user_id          AS "user_id",
                u.username         AS "user_username",
                ue.user_email_id   AS "user_email_id",
                ue.email           AS "user_email",
                ue.created_at      AS "user_email_created_at",
                ue.confirmed_at    AS "user_email_confirmed_at"
            FROM compat_sso_logins cl
            LEFT JOIN compat_sessions cs
              USING (compat_session_id)
            LEFT JOIN users u
              USING (user_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id
        "#,
    );

    query
        .push(" WHERE cs.user_id = ")
        .push_bind(Uuid::from(user.data))
        .generate_pagination("cl.compat_sso_login_id", before, after, first, last)?;

    let span = info_span!(
        "Fetch paginated user compat SSO logins",
        db.statement = query.sql()
    );
    let page: Vec<CompatSsoLoginLookup> = query
        .build_query_as()
        .fetch_all(executor)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let page: Result<Vec<_>, _> = page.into_iter().map(TryInto::try_into).collect();
    Ok((has_previous_page, has_next_page, page?))
}

#[tracing::instrument(skip_all, err)]
pub async fn get_compat_sso_login_by_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<CompatSsoLogin<PostgresqlBackend>, CompatSsoLoginLookupError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT
                cl.compat_sso_login_id,
                cl.login_token     AS "compat_sso_login_token",
                cl.redirect_uri    AS "compat_sso_login_redirect_uri",
                cl.created_at      AS "compat_sso_login_created_at",
                cl.fulfilled_at    AS "compat_sso_login_fulfilled_at",
                cl.exchanged_at    AS "compat_sso_login_exchanged_at",
                cs.compat_session_id AS "compat_session_id?",
                cs.created_at      AS "compat_session_created_at?",
                cs.finished_at     AS "compat_session_finished_at?",
                cs.device_id       AS "compat_session_device_id?",
                u.user_id          AS "user_id?",
                u.username         AS "user_username?",
                ue.user_email_id   AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM compat_sso_logins cl
            LEFT JOIN compat_sessions cs
              USING (compat_session_id)
            LEFT JOIN users u
              USING (user_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id
            WHERE cl.login_token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await?;

    Ok(res.try_into()?)
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        compat_sso_login.id = %login.data,
        compat_sso_login.redirect_uri = %login.redirect_uri,
        compat_session.id,
        compat_session.device.id = device.as_str(),
    ),
    err(Display),
)]
pub async fn fullfill_compat_sso_login(
    conn: impl Acquire<'_, Database = Postgres> + Send,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: User<PostgresqlBackend>,
    mut login: CompatSsoLogin<PostgresqlBackend>,
    device: Device,
) -> Result<CompatSsoLogin<PostgresqlBackend>, anyhow::Error> {
    if !matches!(login.state, CompatSsoLoginState::Pending) {
        bail!("sso login in wrong state");
    };

    let mut txn = conn.begin().await.context("could not start transaction")?;

    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user.id", tracing::field::display(user.data));

    sqlx::query!(
        r#"
            INSERT INTO compat_sessions (compat_session_id, user_id, device_id, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.data),
        device.as_str(),
        created_at,
    )
    .execute(&mut txn)
    .instrument(tracing::info_span!("Insert compat session"))
    .await
    .context("could not insert compat session")?;

    let session = CompatSession {
        data: id,
        user,
        device,
        created_at,
        finished_at: None,
    };

    let fulfilled_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE compat_sso_logins
            SET
                compat_session_id = $2,
                fulfilled_at = $3
            WHERE
                compat_sso_login_id = $1
        "#,
        Uuid::from(login.data),
        Uuid::from(session.data),
        fulfilled_at,
    )
    .execute(&mut txn)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await
    .context("could not update compat SSO login")?;

    let state = CompatSsoLoginState::Fulfilled {
        fulfilled_at,
        session,
    };

    login.state = state;

    txn.commit().await?;

    Ok(login)
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_sso_login.id = %login.data,
        compat_sso_login.redirect_uri = %login.redirect_uri,
    ),
    err(Display),
)]
pub async fn mark_compat_sso_login_as_exchanged(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut login: CompatSsoLogin<PostgresqlBackend>,
) -> Result<CompatSsoLogin<PostgresqlBackend>, anyhow::Error> {
    let (fulfilled_at, session) = match login.state {
        CompatSsoLoginState::Fulfilled {
            fulfilled_at,
            session,
        } => (fulfilled_at, session),
        _ => bail!("sso login in wrong state"),
    };

    let exchanged_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE compat_sso_logins
            SET
                exchanged_at = $2
            WHERE
                compat_sso_login_id = $1
        "#,
        Uuid::from(login.data),
        exchanged_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await
    .context("could not update compat SSO login")?;

    let state = CompatSsoLoginState::Exchanged {
        fulfilled_at,
        exchanged_at,
        session,
    };
    login.state = state;
    Ok(login)
}
