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

use std::borrow::BorrowMut;

use anyhow::{bail, Context};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use mas_data_model::{
    errors::HtmlError, Authentication, BrowserSession, User, UserEmail, UserEmailVerification,
    UserEmailVerificationState,
};
use password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand::rngs::OsRng;
use sqlx::{postgres::types::PgInterval, Acquire, PgExecutor, Postgres, Transaction};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use warp::reject::Reject;

use super::{DatabaseInconsistencyError, PostgresqlBackend};
use crate::IdAndCreationTime;

#[derive(Debug, Clone)]
struct UserLookup {
    user_id: i64,
    user_username: String,
    user_email_id: Option<i64>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("could not find user {username:?}")]
    NotFound {
        username: String,
        #[source]
        source: UserLookupError,
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

#[tracing::instrument(skip(conn, password))]
pub async fn login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: String,
) -> Result<BrowserSession<PostgresqlBackend>, LoginError> {
    let mut txn = conn.begin().await.context("could not start transaction")?;
    let user = lookup_user_by_username(&mut txn, username)
        .await
        .map_err(|source| {
            if source.not_found() {
                LoginError::NotFound {
                    username: username.to_string(),
                    source,
                }
            } else {
                LoginError::Other(source.into())
            }
        })?;

    let mut session = start_session(&mut txn, user).await?;
    authenticate_session(&mut txn, &mut session, password)
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
        })?;

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
        matches!(self, Self::Fetch(sqlx::Error::RowNotFound))
    }
}

struct SessionLookup {
    id: i64,
    user_id: i64,
    username: String,
    created_at: DateTime<Utc>,
    last_authentication_id: Option<i64>,
    last_authd_at: Option<DateTime<Utc>>,
    user_email_id: Option<i64>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl TryInto<BrowserSession<PostgresqlBackend>> for SessionLookup {
    type Error = DatabaseInconsistencyError;

    fn try_into(self) -> Result<BrowserSession<PostgresqlBackend>, Self::Error> {
        let primary_email = match (
            self.user_email_id,
            self.user_email,
            self.user_email_created_at,
            self.user_email_confirmed_at,
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

        let user = User {
            data: self.user_id,
            username: self.username,
            sub: format!("fake-sub-{}", self.user_id),
            primary_email,
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

#[tracing::instrument(skip_all, fields(session.id = id))]
pub async fn lookup_active_session(
    executor: impl PgExecutor<'_>,
    id: i64,
) -> Result<BrowserSession<PostgresqlBackend>, ActiveSessionLookupError> {
    let res = sqlx::query_as!(
        SessionLookup,
        r#"
            SELECT
                s.id,
                u.id AS user_id,
                u.username,
                s.created_at,
                a.id               AS "last_authentication_id?",
                a.created_at       AS "last_authd_at?",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM user_sessions s
            INNER JOIN users u 
                ON s.user_id = u.id
            LEFT JOIN user_session_authentications a
                ON a.session_id = s.id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id
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

#[tracing::instrument(skip_all, fields(user.id = user.data))]
pub async fn start_session(
    executor: impl PgExecutor<'_>,
    user: User<PostgresqlBackend>,
) -> anyhow::Result<BrowserSession<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        IdAndCreationTime,
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

#[tracing::instrument(skip_all, fields(user.id = user.data))]
pub async fn count_active_sessions(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
) -> Result<usize, anyhow::Error> {
    let res = sqlx::query_scalar!(
        r#"
            SELECT COUNT(*) as "count!"
            FROM user_sessions s
            WHERE s.user_id = $1 AND s.active
        "#,
        user.data,
    )
    .fetch_one(executor)
    .await?
    .try_into()?;

    Ok(res)
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

#[tracing::instrument(skip_all, fields(session.id = session.data, user.id = session.user.data))]
pub async fn authenticate_session(
    txn: &mut Transaction<'_, Postgres>,
    session: &mut BrowserSession<PostgresqlBackend>,
    password: String,
) -> Result<(), AuthenticationError> {
    // First, fetch the hashed password from the user associated with that session
    let hashed_password: String = sqlx::query_scalar!(
        r#"
            SELECT up.hashed_password
            FROM user_passwords up
            WHERE up.user_id = $1
            ORDER BY up.created_at DESC
            LIMIT 1
        "#,
        session.user.data,
    )
    .fetch_one(txn.borrow_mut())
    .instrument(tracing::info_span!("Lookup hashed password"))
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
    .instrument(tracing::info_span!("Verify hashed password"))
    .await??;

    // That went well, let's insert the auth info
    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
            INSERT INTO user_session_authentications (session_id)
            VALUES ($1)
            RETURNING id, created_at
        "#,
        session.data,
    )
    .fetch_one(txn.borrow_mut())
    .instrument(tracing::info_span!("Save authentication"))
    .await
    .map_err(AuthenticationError::Save)?;

    session.last_authentication = Some(Authentication {
        data: res.id,
        created_at: res.created_at,
    });

    Ok(())
}

#[tracing::instrument(skip(txn, phf, password))]
pub async fn register_user(
    txn: &mut Transaction<'_, Postgres>,
    phf: impl PasswordHasher,
    username: &str,
    password: &str,
) -> anyhow::Result<User<PostgresqlBackend>> {
    let id: i64 = sqlx::query_scalar!(
        r#"
            INSERT INTO users (username)
            VALUES ($1)
            RETURNING id
        "#,
        username,
    )
    .fetch_one(txn.borrow_mut())
    .instrument(info_span!("Register user"))
    .await
    .context("could not insert user")?;

    let user = User {
        data: id,
        username: username.to_string(),
        sub: format!("fake-sub-{}", id),
        primary_email: None,
    };

    set_password(txn.borrow_mut(), phf, &user, password).await?;

    Ok(user)
}

#[tracing::instrument(skip_all, fields(user.id = user.data))]
pub async fn set_password(
    executor: impl PgExecutor<'_>,
    phf: impl PasswordHasher,
    user: &User<PostgresqlBackend>,
    password: &str,
) -> anyhow::Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = PasswordHash::generate(phf, password, salt.as_str())?;

    sqlx::query_scalar!(
        r#"
            INSERT INTO user_passwords (user_id, hashed_password)
            VALUES ($1, $2)
        "#,
        user.data,
        hashed_password.to_string(),
    )
    .execute(executor)
    .instrument(info_span!("Save user credentials"))
    .await
    .context("could not insert user password")?;

    Ok(())
}

#[tracing::instrument(skip_all, fields(session.id = session.data))]
pub async fn end_session(
    executor: impl PgExecutor<'_>,
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

#[derive(Debug, Error)]
#[error("failed to lookup user")]
pub enum UserLookupError {
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl UserLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Database(sqlx::Error::RowNotFound))
    }
}

#[tracing::instrument(skip(executor))]
pub async fn lookup_user_by_username(
    executor: impl PgExecutor<'_>,
    username: &str,
) -> Result<User<PostgresqlBackend>, UserLookupError> {
    let res = sqlx::query_as!(
        UserLookup,
        r#"
            SELECT 
                u.id            AS user_id, 
                u.username      AS user_username,
                ue.id           AS "user_email_id?",
                ue.email        AS "user_email?",
                ue.created_at   AS "user_email_created_at?",
                ue.confirmed_at AS "user_email_confirmed_at?"
            FROM users u

            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id

            WHERE u.username = $1
        "#,
        username,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch user"))
    .await?;

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

    Ok(User {
        data: res.user_id,
        username: res.user_username,
        sub: format!("fake-sub-{}", res.user_id),
        primary_email,
    })
}

#[derive(Debug, Clone)]
struct UserEmailLookup {
    user_email_id: i64,
    user_email: String,
    user_email_created_at: DateTime<Utc>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailLookup> for UserEmail<PostgresqlBackend> {
    fn from(e: UserEmailLookup) -> UserEmail<PostgresqlBackend> {
        UserEmail {
            data: e.user_email_id,
            email: e.user_email,
            created_at: e.user_email_created_at,
            confirmed_at: e.user_email_confirmed_at,
        }
    }
}

#[tracing::instrument(skip_all, fields(user.id = user.data, %user.username))]
pub async fn get_user_emails(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
) -> Result<Vec<UserEmail<PostgresqlBackend>>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT 
                ue.id           AS "user_email_id",
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1

            ORDER BY ue.email ASC
        "#,
        user.data,
    )
    .fetch_all(executor)
    .instrument(info_span!("Fetch user emails"))
    .await?;

    Ok(res.into_iter().map(Into::into).collect())
}

#[tracing::instrument(skip_all, fields(user.id = user.data, %user.username, email.id = id))]
pub async fn get_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    id: i64,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT 
                ue.id           AS "user_email_id",
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1
              AND ue.id = $2
        "#,
        user.data,
        id,
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch user emails"))
    .await?;

    Ok(res.into())
}

#[tracing::instrument(skip(executor, user), fields(user.id = user.data, %user.username))]
pub async fn add_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    email: String,
) -> anyhow::Result<UserEmail<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            INSERT INTO user_emails (user_id, email)
            VALUES ($1, $2)
            RETURNING 
                id           AS user_email_id,
                email        AS user_email,
                created_at   AS user_email_created_at,
                confirmed_at AS user_email_confirmed_at
        "#,
        user.data,
        email,
    )
    .fetch_one(executor)
    .instrument(info_span!("Add user email"))
    .await
    .context("could not insert user email")?;

    Ok(res.into())
}

#[tracing::instrument(skip(executor))]
pub async fn set_user_email_as_primary(
    executor: impl PgExecutor<'_>,
    email: &UserEmail<PostgresqlBackend>,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
            UPDATE users
            SET primary_email_id = user_emails.id 
            FROM user_emails
            WHERE user_emails.id = $1
              AND users.id       = user_emails.user_id
        "#,
        email.data,
    )
    .execute(executor)
    .instrument(info_span!("Add user email"))
    .await
    .context("could not set user email as primary")?;

    Ok(())
}

#[tracing::instrument(skip(executor))]
pub async fn remove_user_email(
    executor: impl PgExecutor<'_>,
    email: UserEmail<PostgresqlBackend>,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
            DELETE FROM user_emails
            WHERE user_emails.id = $1
        "#,
        email.data,
    )
    .execute(executor)
    .instrument(info_span!("Remove user email"))
    .await
    .context("could not remove user email")?;

    Ok(())
}

#[tracing::instrument(skip(executor))]
pub async fn lookup_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    email: &str,
) -> anyhow::Result<UserEmail<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT 
                ue.id           AS "user_email_id",
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1
              AND ue.email = $2
        "#,
        user.data,
        email,
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email"))
    .await
    .context("could not lookup user email")?;

    Ok(res.into())
}

#[tracing::instrument(skip(executor))]
pub async fn mark_user_email_as_verified(
    executor: impl PgExecutor<'_>,
    mut email: UserEmail<PostgresqlBackend>,
) -> anyhow::Result<UserEmail<PostgresqlBackend>> {
    let confirmed_at = sqlx::query_scalar!(
        r#"
            UPDATE user_emails
            SET confirmed_at = NOW()
            WHERE id = $1
            RETURNING confirmed_at
        "#,
        email.data,
    )
    .fetch_one(executor)
    .instrument(info_span!("Confirm user email"))
    .await
    .context("could not update user email")?;

    email.confirmed_at = confirmed_at;

    Ok(email)
}

struct UserEmailVerificationLookup {
    verification_id: i64,
    verification_expired: bool,
    verification_created_at: DateTime<Utc>,
    verification_consumed_at: Option<DateTime<Utc>>,
    user_email_id: i64,
    user_email: String,
    user_email_created_at: DateTime<Utc>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[tracing::instrument(skip(executor))]
pub async fn lookup_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    code: &str,
    max_age: chrono::Duration,
) -> anyhow::Result<UserEmailVerification<PostgresqlBackend>> {
    // For some reason, we need to convert the type first
    let max_age = PgInterval::try_from(max_age)
        // For some reason, this error type does not let me to just bubble up the error here
        .map_err(|e| anyhow::anyhow!("failed to encode duration: {}", e))?;

    let res = sqlx::query_as!(
        UserEmailVerificationLookup,
        r#"
            SELECT
                ev.id              AS "verification_id",
                (ev.created_at + $2 < NOW()) AS "verification_expired!",
                ev.created_at      AS "verification_created_at",
                ev.consumed_at     AS "verification_consumed_at",
                ue.id              AS "user_email_id",
                ue.email           AS "user_email",
                ue.created_at      AS "user_email_created_at",
                ue.confirmed_at    AS "user_email_confirmed_at"
            FROM user_email_verifications ev
            INNER JOIN user_emails ue
               ON ue.id = ev.user_email_id
            WHERE ev.code = $1
        "#,
        code,
        max_age,
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email verification"))
    .await
    .context("could not lookup user email verification")?;

    let email = UserEmail {
        data: res.user_email_id,
        email: res.user_email,
        created_at: res.user_email_created_at,
        confirmed_at: res.user_email_confirmed_at,
    };

    let state = if res.verification_expired {
        UserEmailVerificationState::Expired
    } else if let Some(when) = res.verification_consumed_at {
        UserEmailVerificationState::AlreadyUsed { when }
    } else {
        UserEmailVerificationState::Valid
    };

    Ok(UserEmailVerification {
        data: res.verification_id,
        email,
        state,
        created_at: res.verification_created_at,
    })
}

#[tracing::instrument(skip(executor))]
pub async fn consume_email_verification(
    executor: impl PgExecutor<'_>,
    mut verification: UserEmailVerification<PostgresqlBackend>,
) -> anyhow::Result<UserEmailVerification<PostgresqlBackend>> {
    if !matches!(verification.state, UserEmailVerificationState::Valid) {
        bail!("user email verification in wrong state");
    }

    let consumed_at = sqlx::query_scalar!(
        r#"
            UPDATE user_email_verifications
            SET consumed_at = NOW()
            WHERE id = $1
            RETURNING consumed_at AS "consumed_at!"
        "#,
        verification.data,
    )
    .fetch_one(executor)
    .instrument(info_span!("Consume user email verification"))
    .await
    .context("could not update user email verification")?;

    verification.state = UserEmailVerificationState::AlreadyUsed { when: consumed_at };

    Ok(verification)
}

#[tracing::instrument(skip(executor, email), fields(email.id = email.data, %email.email))]
pub async fn add_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    email: &UserEmail<PostgresqlBackend>,
    code: &str,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
            INSERT INTO user_email_verifications (user_email_id, code)
            VALUES ($1, $2)
        "#,
        email.data,
        code,
    )
    .execute(executor)
    .instrument(info_span!("Add user email verification code"))
    .await
    .context("could not insert user email verification code")?;

    Ok(())
}
