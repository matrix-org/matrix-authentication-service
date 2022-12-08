// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use anyhow::Context;
use argon2::Argon2;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Authentication, BrowserSession, UpstreamOAuthLink, User, UserEmail, UserEmailVerification,
    UserEmailVerificationState,
};
use password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand::{CryptoRng, Rng};
use sqlx::{Acquire, PgExecutor, Postgres, QueryBuilder, Transaction};
use thiserror::Error;
use tokio::task;
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    Clock, DatabaseError, DatabaseInconsistencyError2, LookupResultExt,
};

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
    NotFound { username: String },

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
    conn: impl Acquire<'_, Database = Postgres> + Send,
    mut rng: impl Rng + Send,
    clock: &Clock,
    username: &str,
    password: &str,
) -> Result<BrowserSession, LoginError> {
    let mut txn = conn.begin().await.context("could not start transaction")?;
    let user = lookup_user_by_username(&mut txn, username)
        .await
        .context("Could not find user by username")?;

    let Some(user) = user else {
        return Err(LoginError::NotFound { username: username.to_owned() });
    };

    let mut session = start_session(&mut txn, &mut rng, clock, user)
        .await
        .context("Could not start session")?;

    authenticate_session(&mut txn, &mut rng, clock, &mut session, password)
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

#[derive(sqlx::FromRow)]
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

impl TryInto<BrowserSession> for SessionLookup {
    type Error = DatabaseInconsistencyError2;

    fn try_into(self) -> Result<BrowserSession, Self::Error> {
        let id = Ulid::from(self.user_id);
        let primary_email = match (
            self.user_email_id,
            self.user_email,
            self.user_email_created_at,
            self.user_email_confirmed_at,
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
                    .row(id))
            }
        };

        let user = User {
            id,
            username: self.username,
            sub: id.to_string(),
            primary_email,
        };

        let last_authentication = match (self.last_authentication_id, self.last_authd_at) {
            (Some(id), Some(created_at)) => Some(Authentication {
                id: id.into(),
                created_at,
            }),
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError2::on(
                    "user_session_authentications",
                ))
            }
        };

        Ok(BrowserSession {
            id: self.user_session_id.into(),
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
) -> Result<Option<BrowserSession>, DatabaseError> {
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
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.try_into()?))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
    ),
    err,
)]
pub async fn get_paginated_user_sessions(
    executor: impl PgExecutor<'_>,
    user: &User,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<BrowserSession>), DatabaseError> {
    let mut query = QueryBuilder::new(
        r#"
            SELECT
                s.user_session_id,
                u.user_id,
                u.username,
                s.created_at,
                a.user_session_authentication_id AS "last_authentication_id",
                a.created_at                     AS "last_authd_at",
                ue.user_email_id   AS "user_email_id",
                ue.email           AS "user_email",
                ue.created_at      AS "user_email_created_at",
                ue.confirmed_at    AS "user_email_confirmed_at"
            FROM user_sessions s
            INNER JOIN users u
                USING (user_id)
            LEFT JOIN user_session_authentications a
                USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id
        "#,
    );

    query
        .push(" WHERE s.finished_at IS NULL AND s.user_id = ")
        .push_bind(Uuid::from(user.id))
        .generate_pagination("s.user_session_id", before, after, first, last)?;

    let span = info_span!("Fetch paginated user emails", db.statement = query.sql());
    let page: Vec<SessionLookup> = query
        .build_query_as()
        .fetch_all(executor)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let page: Result<Vec<_>, _> = page.into_iter().map(TryInto::try_into).collect();
    Ok((has_previous_page, has_next_page, page?))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        user_session.id,
    ),
    err,
)]
pub async fn start_session(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: User,
) -> Result<BrowserSession, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user_session.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO user_sessions (user_session_id, user_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user.id),
        created_at,
    )
    .execute(executor)
    .await?;

    let session = BrowserSession {
        id,
        user,
        created_at,
        last_authentication: None,
    };

    Ok(session)
}

#[tracing::instrument(
    skip_all,
    fields(%user.id),
    err,
)]
pub async fn count_active_sessions(
    executor: impl PgExecutor<'_>,
    user: &User,
) -> Result<i64, DatabaseError> {
    let res = sqlx::query_scalar!(
        r#"
            SELECT COUNT(*) as "count!"
            FROM user_sessions s
            WHERE s.user_id = $1 AND s.finished_at IS NULL
        "#,
        Uuid::from(user.id),
    )
    .fetch_one(executor)
    .await?;

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
        user.id = %user_session.user.id,
        %user_session.id,
        user_session_authentication.id,
    ),
    err,
)]
pub async fn authenticate_session(
    txn: &mut Transaction<'_, Postgres>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user_session: &mut BrowserSession,
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
        Uuid::from(user_session.user.id),
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
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record(
        "user_session_authentication.id",
        tracing::field::display(id),
    );

    sqlx::query!(
        r#"
            INSERT INTO user_session_authentications
                (user_session_authentication_id, user_session_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user_session.id),
        created_at,
    )
    .execute(txn.borrow_mut())
    .instrument(tracing::info_span!("Save authentication"))
    .await
    .map_err(AuthenticationError::Save)?;

    user_session.last_authentication = Some(Authentication { id, created_at });

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user_session.user.id,
        %upstream_oauth_link.id,
        %user_session.id,
        user_session_authentication.id,
    ),
    err,
)]
pub async fn authenticate_session_with_upstream(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user_session: &mut BrowserSession,
    upstream_oauth_link: &UpstreamOAuthLink,
) -> Result<(), sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record(
        "user_session_authentication.id",
        tracing::field::display(id),
    );

    sqlx::query!(
        r#"
            INSERT INTO user_session_authentications
                (user_session_authentication_id, user_session_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user_session.id),
        created_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Save authentication"))
    .await?;

    user_session.last_authentication = Some(Authentication { id, created_at });

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.username = username,
        user.id,
    ),
    err(Debug),
)]
pub async fn register_user(
    txn: &mut Transaction<'_, Postgres>,
    mut rng: impl CryptoRng + Rng + Send,
    clock: &Clock,
    phf: impl PasswordHasher + Send,
    username: &str,
    password: &str,
) -> Result<User, anyhow::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
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
        id,
        username: username.to_owned(),
        sub: id.to_string(),
        primary_email: None,
    };

    set_password(txn.borrow_mut(), &mut rng, clock, phf, &user, password).await?;

    Ok(user)
}

#[tracing::instrument(
    skip_all,
    fields(
        user.username = username,
        user.id,
    ),
    err,
)]
pub async fn register_passwordless_user(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    username: &str,
) -> Result<User, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
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
    .execute(executor)
    .await?;

    Ok(User {
        id,
        username: username.to_owned(),
        sub: id.to_string(),
        primary_email: None,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        user_password.id,
    ),
    err(Debug),
)]
pub async fn set_password(
    executor: impl PgExecutor<'_>,
    mut rng: impl CryptoRng + Rng + Send,
    clock: &Clock,
    phf: impl PasswordHasher + Send,
    user: &User,
    password: &str,
) -> Result<(), anyhow::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user_password.id", tracing::field::display(id));

    let salt = SaltString::generate(&mut rng);
    let hashed_password = PasswordHash::generate(phf, password, salt.as_str())?;

    sqlx::query_scalar!(
        r#"
            INSERT INTO user_passwords (user_password_id, user_id, hashed_password, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.id),
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
    fields(%user_session.id),
    err,
)]
pub async fn end_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    user_session: &BrowserSession,
) -> Result<(), DatabaseError> {
    let now = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE user_sessions
            SET finished_at = $1
            WHERE user_session_id = $2
        "#,
        now,
        Uuid::from(user_session.id),
    )
    .execute(executor)
    .instrument(info_span!("End session"))
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}

#[tracing::instrument(
    skip_all,
    fields(user.username = username),
    err,
)]
pub async fn lookup_user_by_username(
    executor: impl PgExecutor<'_>,
    username: &str,
) -> Result<Option<User>, DatabaseError> {
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
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let id = Ulid::from(res.user_id);
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
                .row(id)
                .into())
        }
    };

    Ok(Some(User {
        id,
        username: res.user_username,
        sub: id.to_string(),
        primary_email,
    }))
}

#[tracing::instrument(
    skip_all,
    fields(user.id = %id),
    err,
)]
pub async fn lookup_user(executor: impl PgExecutor<'_>, id: Ulid) -> Result<User, DatabaseError> {
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

            WHERE u.user_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Fetch user"))
    .await?;

    let id = Ulid::from(res.user_id);
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
                .row(id)
                .into())
        }
    };

    Ok(User {
        id,
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

#[derive(Debug, Clone, sqlx::FromRow)]
struct UserEmailLookup {
    user_email_id: Uuid,
    user_email: String,
    user_email_created_at: DateTime<Utc>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailLookup> for UserEmail {
    fn from(e: UserEmailLookup) -> UserEmail {
        UserEmail {
            id: e.user_email_id.into(),
            email: e.user_email,
            created_at: e.user_email_created_at,
            confirmed_at: e.user_email_confirmed_at,
        }
    }
}

#[tracing::instrument(
    skip_all,
    fields(%user.id, %user.username),
    err,
)]
pub async fn get_user_emails(
    executor: impl PgExecutor<'_>,
    user: &User,
) -> Result<Vec<UserEmail>, sqlx::Error> {
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
        Uuid::from(user.id),
    )
    .fetch_all(executor)
    .instrument(info_span!("Fetch user emails"))
    .await?;

    Ok(res.into_iter().map(Into::into).collect())
}

#[tracing::instrument(
    skip_all,
    fields(%user.id, %user.username),
    err,
)]
pub async fn count_user_emails(
    executor: impl PgExecutor<'_>,
    user: &User,
) -> Result<i64, sqlx::Error> {
    let res = sqlx::query_scalar!(
        r#"
            SELECT COUNT(*)
            FROM user_emails ue
            WHERE ue.user_id = $1
        "#,
        Uuid::from(user.id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Count user emails"))
    .await?;

    Ok(res.unwrap_or_default())
}

#[tracing::instrument(
    skip_all,
    fields(%user.id, %user.username),
    err,
)]
pub async fn get_paginated_user_emails(
    executor: impl PgExecutor<'_>,
    user: &User,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<UserEmail>), DatabaseError> {
    let mut query = QueryBuilder::new(
        r#"
            SELECT
                ue.user_email_id,
                ue.email        AS "user_email",
                ue.created_at   AS "user_email_created_at",
                ue.confirmed_at AS "user_email_confirmed_at"
            FROM user_emails ue
        "#,
    );

    query
        .push(" WHERE ue.user_id = ")
        .push_bind(Uuid::from(user.id))
        .generate_pagination("ue.user_email_id", before, after, first, last)?;

    let span = info_span!("Fetch paginated user sessions", db.statement = query.sql());
    let page: Vec<UserEmailLookup> = query
        .build_query_as()
        .fetch_all(executor)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    Ok((
        has_previous_page,
        has_next_page,
        page.into_iter().map(Into::into).collect(),
    ))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
        user_email.id = %id,
    ),
    err,
)]
pub async fn get_user_email(
    executor: impl PgExecutor<'_>,
    user: &User,
    id: Ulid,
) -> Result<UserEmail, sqlx::Error> {
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
        Uuid::from(user.id),
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
        %user.id,
        %user.username,
        user_email.id,
        user_email.email = %email,
    ),
    err,
)]
pub async fn add_user_email(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: &User,
    email: String,
) -> Result<UserEmail, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user_email.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO user_emails (user_email_id, user_id, email, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.id),
        &email,
        created_at,
    )
    .execute(executor)
    .instrument(info_span!("Add user email"))
    .await?;

    Ok(UserEmail {
        id,
        email,
        created_at,
        confirmed_at: None,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        %user_email.id,
        %user_email.email,
    ),
    err(Display),
)]
pub async fn set_user_email_as_primary(
    executor: impl PgExecutor<'_>,
    user_email: &UserEmail,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE users
            SET primary_user_email_id = user_emails.user_email_id
            FROM user_emails
            WHERE user_emails.user_email_id = $1
              AND users.user_id = user_emails.user_id
        "#,
        Uuid::from(user_email.id),
    )
    .execute(executor)
    .instrument(info_span!("Add user email"))
    .await?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        %user_email.id,
        %user_email.email,
    ),
    err,
)]
pub async fn remove_user_email(
    executor: impl PgExecutor<'_>,
    user_email: UserEmail,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            DELETE FROM user_emails
            WHERE user_emails.user_email_id = $1
        "#,
        Uuid::from(user_email.id),
    )
    .execute(executor)
    .instrument(info_span!("Remove user email"))
    .await?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        user_email.email = email,
    ),
    err,
)]
pub async fn lookup_user_email(
    executor: impl PgExecutor<'_>,
    user: &User,
    email: &str,
) -> Result<Option<UserEmail>, sqlx::Error> {
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
        Uuid::from(user.id),
        email,
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email"))
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        user_email.id = %id,
    ),
    err,
)]
pub async fn lookup_user_email_by_id(
    executor: impl PgExecutor<'_>,
    user: &User,
    id: Ulid,
) -> Result<Option<UserEmail>, DatabaseError> {
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
        Uuid::from(user.id),
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email"))
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

#[tracing::instrument(
    skip_all,
    fields(%user_email.id),
    err,
)]
pub async fn mark_user_email_as_verified(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut user_email: UserEmail,
) -> Result<UserEmail, sqlx::Error> {
    let confirmed_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE user_emails
            SET confirmed_at = $2
            WHERE user_email_id = $1
        "#,
        Uuid::from(user_email.id),
        confirmed_at,
    )
    .execute(executor)
    .instrument(info_span!("Confirm user email"))
    .await?;

    user_email.confirmed_at = Some(confirmed_at);

    Ok(user_email)
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
    fields(%user_email.id),
    err,
)]
pub async fn lookup_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    user_email: UserEmail,
    code: &str,
) -> Result<Option<UserEmailVerification>, DatabaseError> {
    let now = clock.now();

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
        Uuid::from(user_email.id),
    )
    .fetch_one(executor)
    .instrument(info_span!("Lookup user email verification"))
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let state = if let Some(when) = res.consumed_at {
        UserEmailVerificationState::AlreadyUsed { when }
    } else if res.expires_at < now {
        UserEmailVerificationState::Expired {
            when: res.expires_at,
        }
    } else {
        UserEmailVerificationState::Valid
    };

    Ok(Some(UserEmailVerification {
        id: res.user_email_confirmation_code_id.into(),
        code: res.code,
        email: user_email,
        state,
        created_at: res.created_at,
    }))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user_email_verification.id,
    ),
    err,
)]
pub async fn consume_email_verification(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut user_email_verification: UserEmailVerification,
) -> Result<UserEmailVerification, DatabaseError> {
    if !matches!(
        user_email_verification.state,
        UserEmailVerificationState::Valid
    ) {
        return Err(DatabaseError::invalid_operation());
    }

    let consumed_at = clock.now();

    sqlx::query!(
        r#"
            UPDATE user_email_confirmation_codes
            SET consumed_at = $2
            WHERE user_email_confirmation_code_id = $1
        "#,
        Uuid::from(user_email_verification.id),
        consumed_at
    )
    .execute(executor)
    .instrument(info_span!("Consume user email verification"))
    .await?;

    user_email_verification.state = UserEmailVerificationState::AlreadyUsed { when: consumed_at };

    Ok(user_email_verification)
}

#[tracing::instrument(
    skip_all,
    fields(
        %user_email.id,
        %user_email.email,
        user_email_confirmation.id,
        user_email_confirmation.code = code,
    ),
    err,
)]
pub async fn add_user_email_verification_code(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user_email: UserEmail,
    max_age: chrono::Duration,
    code: String,
) -> Result<UserEmailVerification, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user_email_confirmation.id", tracing::field::display(id));
    let expires_at = created_at + max_age;

    sqlx::query!(
        r#"
            INSERT INTO user_email_confirmation_codes
              (user_email_confirmation_code_id, user_email_id, code, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(user_email.id),
        code,
        created_at,
        expires_at,
    )
    .execute(executor)
    .instrument(info_span!("Add user email verification code"))
    .await?;

    let verification = UserEmailVerification {
        id,
        email: user_email,
        code,
        created_at,
        state: UserEmailVerificationState::Valid,
    };

    Ok(verification)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_user_registration_and_login(pool: sqlx::PgPool) -> anyhow::Result<()> {
        let clock = Clock::default();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let mut txn = pool.begin().await?;

        let exists = username_exists(&mut txn, "john").await?;
        assert!(!exists);

        let hasher = Argon2::default();
        let user = register_user(&mut txn, &mut rng, &clock, hasher, "john", "hunter2").await?;
        assert_eq!(user.username, "john");

        let exists = username_exists(&mut txn, "john").await?;
        assert!(exists);

        let session = login(&mut txn, &mut rng, &clock, "john", "hunter2").await?;
        assert_eq!(session.user.id, user.id);

        let user2 = lookup_user_by_username(&mut txn, "john")
            .await?
            .context("Could not find user")?;
        assert_eq!(user.id, user2.id);

        txn.commit().await?;

        Ok(())
    }
}
