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
    Authentication, BrowserSession, User, UserEmail, UserEmailVerification,
    UserEmailVerificationState,
};
use password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand::thread_rng;
use sqlx::{Acquire, PgExecutor, Postgres, Transaction};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use super::{DatabaseInconsistencyError, PostgresqlBackend};

#[derive(Debug, Clone)]
struct UserLookup {
    user_id: Uuid,
    user_username: String,
    user_email_id: Option<Uuid>,
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

#[tracing::instrument(
    skip_all,
    fields(user.username = username),
    err,
)]
pub async fn login(
    conn: impl Acquire<'_, Database = Postgres>,
    username: &str,
    password: &str,
) -> Result<BrowserSession<PostgresqlBackend>, LoginError> {
    let mut txn = conn.begin().await.context("could not start transaction")?;
    let user = lookup_user_by_username(&mut txn, username)
        .await
        .map_err(|source| {
            if source.not_found() {
                LoginError::NotFound {
                    username: username.to_owned(),
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
                    username: username.to_owned(),
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

impl ActiveSessionLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, Self::Fetch(sqlx::Error::RowNotFound))
    }
}

struct SessionLookup {
    user_session_id: Uuid,
    user_id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
    last_authentication_id: Option<Uuid>,
    last_authd_at: Option<DateTime<Utc>>,
    user_email_id: Option<Uuid>,
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
                data: id.into(),
                email,
                created_at,
                confirmed_at,
            }),
            (None, None, None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        let id = Ulid::from(self.user_id);
        let user = User {
            data: id,
            username: self.username,
            sub: id.to_string(),
            primary_email,
        };

        let last_authentication = match (self.last_authentication_id, self.last_authd_at) {
            (Some(id), Some(created_at)) => Some(Authentication {
                data: id.into(),
                created_at,
            }),
            (None, None) => None,
            _ => return Err(DatabaseInconsistencyError),
        };

        Ok(BrowserSession {
            data: self.user_session_id.into(),
            user,
            created_at: self.created_at,
            last_authentication,
        })
    }
}

#[tracing::instrument(
    skip_all,
    fields(user_session.id = %id),
    err,
)]
pub async fn lookup_active_session(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<BrowserSession<PostgresqlBackend>, ActiveSessionLookupError> {
    let res = sqlx::query_as!(
        SessionLookup,
        r#"
            SELECT
                s.user_session_id,
                u.user_id,
                u.username,
                s.created_at,
                a.user_session_authentication_id AS "last_authentication_id?",
                a.created_at                     AS "last_authd_at?",
                ue.user_email_id   AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM user_sessions s
            INNER JOIN users u
                USING (user_id)
            LEFT JOIN user_session_authentications a
                USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id
            WHERE s.user_session_id = $1 AND s.finished_at IS NULL
            ORDER BY a.created_at DESC
            LIMIT 1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .await?
    .try_into()?;

    Ok(res)
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user_session.id,
    ),
    err(Display),
)]
pub async fn start_session(
    executor: impl PgExecutor<'_>,
    user: User<PostgresqlBackend>,
) -> Result<BrowserSession<PostgresqlBackend>, anyhow::Error> {
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    tracing::Span::current().record("user_session.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO user_sessions (user_session_id, user_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user.data),
        created_at,
    )
    .execute(executor)
    .await
    .context("could not create session")?;

    let session = BrowserSession {
        data: id,
        user,
        created_at,
        last_authentication: None,
    };

    Ok(session)
}

#[tracing::instrument(
    skip_all,
    fields(user.id = %user.data),
    err(Display),
)]
pub async fn count_active_sessions(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
) -> Result<usize, anyhow::Error> {
    let res = sqlx::query_scalar!(
        r#"
            SELECT COUNT(*) as "count!"
            FROM user_sessions s
            WHERE s.user_id = $1 AND s.finished_at IS NULL
        "#,
        Uuid::from(user.data),
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

#[tracing::instrument(
    skip_all,
    fields(
        session.id = %session.data,
        user.id = %session.user.data
    ),
    err,
)]
pub async fn authenticate_session(
    txn: &mut Transaction<'_, Postgres>,
    session: &mut BrowserSession<PostgresqlBackend>,
    password: &str,
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
        Uuid::from(session.user.data),
    )
    .fetch_one(txn.borrow_mut())
    .instrument(tracing::info_span!("Lookup hashed password"))
    .await
    .map_err(AuthenticationError::Fetch)?;

    // TODO: pass verifiers list as parameter
    // Verify the password in a blocking thread to avoid blocking the async executor
    let password = password.to_owned();
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
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    sqlx::query!(
        r#"
            INSERT INTO user_session_authentications
                (user_session_authentication_id, user_session_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(session.data),
        created_at,
    )
    .execute(txn.borrow_mut())
    .instrument(tracing::info_span!("Save authentication"))
    .await
    .map_err(AuthenticationError::Save)?;

    session.last_authentication = Some(Authentication {
        data: id,
        created_at,
    });

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.username = username,
        user.id,
    ),
    err(Display),
)]
pub async fn register_user(
    txn: &mut Transaction<'_, Postgres>,
    phf: impl PasswordHasher,
    username: &str,
    password: &str,
) -> Result<User<PostgresqlBackend>, anyhow::Error> {
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    tracing::Span::current().record("user.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO users (user_id, username, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        username,
        created_at,
    )
    .execute(txn.borrow_mut())
    .instrument(info_span!("Register user"))
    .await
    .context("could not insert user")?;

    let user = User {
        data: id,
        username: username.to_owned(),
        sub: id.to_string(),
        primary_email: None,
    };

    set_password(txn.borrow_mut(), phf, &user, password).await?;

    Ok(user)
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user_password.id,
    ),
    err(Display),
)]
pub async fn set_password(
    executor: impl PgExecutor<'_>,
    phf: impl PasswordHasher,
    user: &User<PostgresqlBackend>,
    password: &str,
) -> Result<(), anyhow::Error> {
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    tracing::Span::current().record("user_password.id", tracing::field::display(id));

    let salt = SaltString::generate(thread_rng());
    let hashed_password = PasswordHash::generate(phf, password, salt.as_str())?;

    sqlx::query_scalar!(
        r#"
            INSERT INTO user_passwords (user_password_id, user_id, hashed_password, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.data),
        hashed_password.to_string(),
        created_at,
    )
    .execute(executor)
    .instrument(info_span!("Save user credentials"))
    .await
    .context("could not insert user password")?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(user_session.id = %session.data),
    err(Display),
)]
pub async fn end_session(
    executor: impl PgExecutor<'_>,
    session: &BrowserSession<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    let now = Utc::now();
    let res = sqlx::query!(
        r#"
            UPDATE user_sessions
            SET finished_at = $1
            WHERE user_session_id = $2
        "#,
        now,
        Uuid::from(session.data),
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

#[tracing::instrument(
    skip_all,
    fields(user.username = username),
    err,
)]
pub async fn lookup_user_by_username(
    executor: impl PgExecutor<'_>,
    username: &str,
) -> Result<User<PostgresqlBackend>, UserLookupError> {
    let res = sqlx::query_as!(
        UserLookup,
        r#"
            SELECT
                u.user_id,
                u.username       AS user_username,
                ue.user_email_id AS "user_email_id?",
                ue.email         AS "user_email?",
                ue.created_at    AS "user_email_created_at?",
                ue.confirmed_at  AS "user_email_confirmed_at?"
            FROM users u

            LEFT JOIN user_emails ue
              USING (user_id)

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
            data: id.into(),
            email,
            created_at,
            confirmed_at,
        }),
        (None, None, None, None) => None,
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let id = Ulid::from(res.user_id);
    Ok(User {
        data: id,
        username: res.user_username,
        sub: id.to_string(),
        primary_email,
    })
}

#[tracing::instrument(
    skip_all,
    fields(user.username = username),
    err,
)]
pub async fn username_exists(
    executor: impl PgExecutor<'_>,
    username: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
            SELECT EXISTS(
                SELECT 1 FROM users WHERE username = $1
            ) AS "exists!"
        "#,
        username
    )
    .fetch_one(executor)
    .await
}

#[derive(Debug, Clone)]
struct UserEmailLookup {
    user_email_id: Uuid,
    user_email: String,
    user_email_created_at: DateTime<Utc>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailLookup> for UserEmail<PostgresqlBackend> {
    fn from(e: UserEmailLookup) -> UserEmail<PostgresqlBackend> {
        UserEmail {
            data: e.user_email_id.into(),
            email: e.user_email,
            created_at: e.user_email_created_at,
            confirmed_at: e.user_email_confirmed_at,
        }
    }
}

#[tracing::instrument(
    skip_all,
    fields(user.id = %user.data, user.username = user.username),
    err(Display),
)]
pub async fn get_user_emails(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
) -> Result<Vec<UserEmail<PostgresqlBackend>>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT
                ue.user_email_id,
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1

            ORDER BY ue.email ASC
        "#,
        Uuid::from(user.data),
    )
    .fetch_all(executor)
    .instrument(info_span!("Fetch user emails"))
    .await?;

    Ok(res.into_iter().map(Into::into).collect())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user.username = user.username,
        user_email.id = %id,
    ),
    err(Display),
)]
pub async fn get_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    id: Ulid,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT
                ue.user_email_id,
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1
              AND ue.user_email_id = $2
        "#,
        Uuid::from(user.data),
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch user emails"))
    .await?;

    Ok(res.into())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user.username = user.username,
        user_email.id,
        user_email.email = %email,
    ),
    err(Display),
)]
pub async fn add_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    email: String,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    tracing::Span::current().record("user_email.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO user_emails (user_email_id, user_id, email, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.data),
        &email,
        created_at,
    )
    .execute(executor)
    .instrument(info_span!("Add user email"))
    .await
    .context("could not insert user email")?;

    Ok(UserEmail {
        data: id,
        email,
        created_at,
        confirmed_at: None,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email.id = %email.data,
        user_email.email = %email.email,
    ),
    err(Display),
)]
pub async fn set_user_email_as_primary(
    executor: impl PgExecutor<'_>,
    email: &UserEmail<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"
            UPDATE users
            SET primary_user_email_id = user_emails.user_email_id
            FROM user_emails
            WHERE user_emails.user_email_id = $1
              AND users.user_id = user_emails.user_id
        "#,
        Uuid::from(email.data),
    )
    .execute(executor)
    .instrument(info_span!("Add user email"))
    .await
    .context("could not set user email as primary")?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email.id = %email.data,
        user_email.email = %email.email,
    ),
    err(Display),
)]
pub async fn remove_user_email(
    executor: impl PgExecutor<'_>,
    email: UserEmail<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"
            DELETE FROM user_emails
            WHERE user_emails.user_email_id = $1
        "#,
        Uuid::from(email.data),
    )
    .execute(executor)
    .instrument(info_span!("Remove user email"))
    .await
    .context("could not remove user email")?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user_email.email = email,
    ),
    err(Display),
)]
pub async fn lookup_user_email(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    email: &str,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT
                ue.user_email_id,
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1
              AND ue.email = $2
        "#,
        Uuid::from(user.data),
        email,
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email"))
    .await
    .context("could not lookup user email")?;

    Ok(res.into())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user.data,
        user_email.id = %id,
    ),
    err(Display),
)]
pub async fn lookup_user_email_by_id(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    id: Ulid,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let res = sqlx::query_as!(
        UserEmailLookup,
        r#"
            SELECT
                ue.user_email_id,
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue

            WHERE ue.user_id = $1
              AND ue.user_email_id = $2
        "#,
        Uuid::from(user.data),
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email"))
    .await
    .context("could not lookup user email")?;

    Ok(res.into())
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email.id = %email.data,
    ),
    err(Display),
)]
pub async fn mark_user_email_as_verified(
    executor: impl PgExecutor<'_>,
    mut email: UserEmail<PostgresqlBackend>,
) -> Result<UserEmail<PostgresqlBackend>, anyhow::Error> {
    let confirmed_at = Utc::now();
    sqlx::query!(
        r#"
            UPDATE user_emails
            SET confirmed_at = $2
            WHERE user_email_id = $1
        "#,
        Uuid::from(email.data),
        confirmed_at,
    )
    .execute(executor)
    .instrument(info_span!("Confirm user email"))
    .await
    .context("could not update user email")?;

    email.confirmed_at = Some(confirmed_at);

    Ok(email)
}

struct UserEmailConfirmationCodeLookup {
    user_email_confirmation_code_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email.id = %email.data,
    ),
    err(Display),
)]
pub async fn lookup_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    email: UserEmail<PostgresqlBackend>,
    code: &str,
) -> Result<UserEmailVerification<PostgresqlBackend>, anyhow::Error> {
    let now = Utc::now();

    let res = sqlx::query_as!(
        UserEmailConfirmationCodeLookup,
        r#"
            SELECT
                ec.user_email_confirmation_code_id,
                ec.code,
                ec.created_at,
                ec.expires_at,
                ec.consumed_at
            FROM user_email_confirmation_codes ec
            WHERE ec.code = $1
              AND ec.user_email_id = $2
        "#,
        code,
        Uuid::from(email.data),
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email verification"))
    .await
    .context("could not lookup user email verification")?;

    let state = if let Some(when) = res.consumed_at {
        UserEmailVerificationState::AlreadyUsed { when }
    } else if res.expires_at < now {
        UserEmailVerificationState::Expired {
            when: res.expires_at,
        }
    } else {
        UserEmailVerificationState::Valid
    };

    Ok(UserEmailVerification {
        data: res.user_email_confirmation_code_id.into(),
        code: res.code,
        email,
        state,
        created_at: res.created_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email_verification.id = %verification.data,
    ),
    err(Display),
)]
pub async fn consume_email_verification(
    executor: impl PgExecutor<'_>,
    mut verification: UserEmailVerification<PostgresqlBackend>,
) -> Result<UserEmailVerification<PostgresqlBackend>, anyhow::Error> {
    if !matches!(verification.state, UserEmailVerificationState::Valid) {
        bail!("user email verification in wrong state");
    }

    let consumed_at = Utc::now();

    sqlx::query!(
        r#"
            UPDATE user_email_confirmation_codes
            SET consumed_at = $2
            WHERE user_email_confirmation_code_id = $1
        "#,
        Uuid::from(verification.data),
        consumed_at
    )
    .execute(executor)
    .instrument(info_span!("Consume user email verification"))
    .await
    .context("could not update user email verification")?;

    verification.state = UserEmailVerificationState::AlreadyUsed { when: consumed_at };

    Ok(verification)
}

#[tracing::instrument(
    skip_all,
    fields(
        user_email.id = %email.data,
        user_email.email = %email.email,
        user_email_confirmation.id,
        user_email_confirmation.code = code,
    ),
    err(Display),
)]
pub async fn add_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    email: UserEmail<PostgresqlBackend>,
    max_age: chrono::Duration,
    code: String,
) -> Result<UserEmailVerification<PostgresqlBackend>, anyhow::Error> {
    let created_at = Utc::now();
    let id = Ulid::from_datetime(created_at.into());
    tracing::Span::current().record("user_email_confirmation.id", tracing::field::display(id));
    let expires_at = created_at + max_age;

    sqlx::query!(
        r#"
            INSERT INTO user_email_confirmation_codes
              (user_email_confirmation_code_id, user_email_id, code, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(email.data),
        code,
        created_at,
        expires_at,
    )
    .execute(executor)
    .instrument(info_span!("Add user email verification code"))
    .await
    .context("could not insert user email verification code")?;

    let verification = UserEmailVerification {
        data: id,
        email,
        code,
        created_at,
        state: UserEmailVerificationState::Valid,
    };

    Ok(verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_user_registration_and_login(pool: sqlx::PgPool) -> anyhow::Result<()> {
        let mut txn = pool.begin().await?;

        let exists = username_exists(&mut txn, "john").await?;
        assert!(!exists);

        let hasher = Argon2::default();
        let user = register_user(&mut txn, hasher, "john", "hunter2").await?;
        assert_eq!(user.username, "john");

        let exists = username_exists(&mut txn, "john").await?;
        assert!(exists);

        let session = login(&mut txn, "john", "hunter2").await?;
        assert_eq!(session.user.data, user.data);

        let user2 = lookup_user_by_username(&mut txn, "john").await?;
        assert_eq!(user.data, user2.data);

        txn.commit().await?;

        Ok(())
    }
}
