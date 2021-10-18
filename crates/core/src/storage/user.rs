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

use std::{borrow::BorrowMut, convert::TryInto};

use anyhow::Context;
use argon2::Argon2;
use chrono::{DateTime, Utc};
use mas_data_model::{errors::HtmlError, Authentication, BrowserSession, User};
use password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand::rngs::OsRng;
use sqlx::{Acquire, Executor, FromRow, Postgres, Transaction};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use warp::reject::Reject;

use super::{DatabaseInconsistencyError, PostgresqlBackend};

#[derive(Debug, Clone, FromRow)]
struct UserLookup {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("could not find user {username:?}")]
    NotFound {
        username: String,
        #[source]
        source: sqlx::Error,
    },

    #[error("authentication failed for {username:?}")]
    Authentication {
        username: String,
        #[source]
        source: AuthenticationError,
    },

    #[error("failed to login")]
    Other(#[from] anyhow::Error),
}

impl HtmlError for LoginError {
    fn html_display(&self) -> String {
        match self {
            LoginError::NotFound { .. } => "Could not find user".to_string(),
            LoginError::Authentication { .. } => "Failed to authenticate user".to_string(),
            LoginError::Other(e) => format!("Internal error: <pre>{}</pre>", e),
        }
    }
}

pub async fn login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: String,
) -> Result<BrowserSession<PostgresqlBackend>, LoginError> {
    let mut txn = conn.begin().await.context("could not start transaction")?;
    let user = lookup_user_by_username(&mut txn, username)
        .await
        .map_err(|source| {
            if matches!(source, sqlx::Error::RowNotFound) {
                LoginError::NotFound {
                    username: username.to_string(),
                    source,
                }
            } else {
                LoginError::Other(source.into())
            }
        })?;

    let mut session = start_session(&mut txn, user).await?;
    session.last_authentication = Some(
        authenticate_session(&mut txn, &session, password)
            .await
            .map_err(|source| {
                if matches!(source, AuthenticationError::Password { .. }) {
                    LoginError::Authentication {
                        username: username.to_string(),
                        source,
                    }
                } else {
                    LoginError::Other(source.into())
                }
            })?,
    );
    txn.commit().await.context("could not commit transaction")?;
    Ok(session)
}

#[derive(Debug, Error)]
#[error("could not fetch session")]
pub enum ActiveSessionLookupError {
    Fetch(#[from] sqlx::Error),
    Conversion(#[from] DatabaseInconsistencyError),
}

impl Reject for ActiveSessionLookupError {}

impl ActiveSessionLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(
            self,
            ActiveSessionLookupError::Fetch(sqlx::Error::RowNotFound)
        )
    }
}

struct SessionLookup {
    id: i64,
    user_id: i64,
    username: String,
    created_at: DateTime<Utc>,
    last_authentication_id: Option<i64>,
    last_authd_at: Option<DateTime<Utc>>,
}

impl TryInto<BrowserSession<PostgresqlBackend>> for SessionLookup {
    type Error = DatabaseInconsistencyError;

    fn try_into(self) -> Result<BrowserSession<PostgresqlBackend>, Self::Error> {
        let user = User {
            data: self.user_id,
            username: self.username,
            sub: format!("fake-sub-{}", self.user_id),
        };

        let last_authentication = match (self.last_authentication_id, self.last_authd_at) {
            (Some(id), Some(created_at)) => Some(Authentication {
                data: id,
                created_at,
            }),
            (None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        Ok(BrowserSession {
            data: self.id,
            user,
            created_at: self.created_at,
            last_authentication,
        })
    }
}

pub async fn lookup_active_session(
    executor: impl Executor<'_, Database = Postgres>,
    id: i64,
) -> Result<BrowserSession<PostgresqlBackend>, ActiveSessionLookupError> {
    let res = sqlx::query_as!(
        SessionLookup,
        r#"
            SELECT
                s.id,
                u.id as user_id,
                u.username,
                s.created_at,
                a.id as "last_authentication_id?",
                a.created_at as "last_authd_at?"
            FROM user_sessions s
            INNER JOIN users u 
                ON s.user_id = u.id
            LEFT JOIN user_session_authentications a
                ON a.session_id = s.id
            WHERE s.id = $1 AND s.active
            ORDER BY a.created_at DESC
            LIMIT 1
        "#,
        id,
    )
    .fetch_one(executor)
    .await?
    .try_into()?;

    Ok(res)
}

#[derive(FromRow)]
struct SessionStartResult {
    id: i64,
    created_at: DateTime<Utc>,
}

pub async fn start_session(
    executor: impl Executor<'_, Database = Postgres>,
    user: User<PostgresqlBackend>,
) -> anyhow::Result<BrowserSession<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        SessionStartResult,
        r#"
            INSERT INTO user_sessions (user_id)
            VALUES ($1)
            RETURNING id, created_at
        "#,
        user.data,
    )
    .fetch_one(executor)
    .await
    .context("could not create session")?;

    let session = BrowserSession {
        data: res.id,
        user,
        created_at: res.created_at,
        last_authentication: None,
    };

    Ok(session)
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("could not verify password")]
    Password(#[from] password_hash::Error),

    #[error("could not fetch user password hash")]
    Fetch(sqlx::Error),

    #[error("could not save session auth")]
    Save(sqlx::Error),

    #[error("runtime error")]
    Internal(#[from] tokio::task::JoinError),
}

#[derive(FromRow)]
struct AuthenticationInsertionResult {
    id: i64,
    created_at: DateTime<Utc>,
}

pub async fn authenticate_session(
    txn: &mut Transaction<'_, Postgres>,
    session: &BrowserSession<PostgresqlBackend>,
    password: String,
) -> Result<Authentication<PostgresqlBackend>, AuthenticationError> {
    // First, fetch the hashed password from the user associated with that session
    let hashed_password: String = sqlx::query_scalar!(
        r#"
            SELECT u.hashed_password
            FROM user_sessions s
            INNER JOIN users u
               ON u.id = s.user_id 
            WHERE s.id = $1
        "#,
        session.data,
    )
    .fetch_one(txn.borrow_mut())
    .await
    .map_err(AuthenticationError::Fetch)?;

    // TODO: pass verifiers list as parameter
    // Verify the password in a blocking thread to avoid blocking the async executor
    task::spawn_blocking(move || {
        let context = Argon2::default();
        let hasher = PasswordHash::new(&hashed_password).map_err(AuthenticationError::Password)?;
        hasher
            .verify_password(&[&context], &password)
            .map_err(AuthenticationError::Password)
    })
    .await??;

    // That went well, let's insert the auth info
    let res = sqlx::query_as!(
        AuthenticationInsertionResult,
        r#"
            INSERT INTO user_session_authentications (session_id)
            VALUES ($1)
            RETURNING id, created_at
        "#,
        session.data,
    )
    .fetch_one(txn.borrow_mut())
    .await
    .map_err(AuthenticationError::Save)?;

    Ok(Authentication {
        data: res.id,
        created_at: res.created_at,
    })
}

pub async fn register_user(
    executor: impl Executor<'_, Database = Postgres>,
    phf: impl PasswordHasher,
    username: &str,
    password: &str,
) -> anyhow::Result<User<PostgresqlBackend>> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = PasswordHash::generate(phf, password, salt.as_str())?;

    let id: i64 = sqlx::query_scalar!(
        r#"
            INSERT INTO users (username, hashed_password)
            VALUES ($1, $2)
            RETURNING id
        "#,
        username,
        hashed_password.to_string(),
    )
    .fetch_one(executor)
    .instrument(info_span!("Register user"))
    .await
    .context("could not insert user")?;

    Ok(User {
        data: id,
        username: username.to_string(),
        sub: format!("fake-sub-{}", id),
    })
}

pub async fn end_session(
    executor: impl Executor<'_, Database = Postgres>,
    session: &BrowserSession<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        "UPDATE user_sessions SET active = FALSE WHERE id = $1",
        session.data,
    )
    .execute(executor)
    .instrument(info_span!("End session"))
    .await
    .context("could not end session")?;

    match res.rows_affected() {
        1 => Ok(()),
        0 => Err(anyhow::anyhow!("no row affected")),
        _ => Err(anyhow::anyhow!("too many row affected")),
    }
}

pub async fn lookup_user_by_username(
    executor: impl Executor<'_, Database = Postgres>,
    username: &str,
) -> Result<User<PostgresqlBackend>, sqlx::Error> {
    let res = sqlx::query_as!(
        UserLookup,
        r#"
            SELECT id, username
            FROM users
            WHERE username = $1
        "#,
        username,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch user"))
    .await?;

    Ok(User {
        data: res.id,
        username: res.username,
        sub: format!("fake-sub-{}", res.id),
    })
}
