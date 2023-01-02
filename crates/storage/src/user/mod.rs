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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Authentication, BrowserSession, User};
use rand::{Rng, RngCore};
use sqlx::{PgConnection, PgExecutor, QueryBuilder};
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt,
};

mod authentication;
mod email;
mod password;

pub use self::{
    authentication::{authenticate_session_with_password, authenticate_session_with_upstream},
    email::{PgUserEmailRepository, UserEmailRepository},
    password::{add_user_password, lookup_user_password},
};

#[async_trait]
pub trait UserRepository: Send + Sync {
    type Error;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        username: String,
    ) -> Result<User, Self::Error>;
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error>;
}

pub struct PgUserRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRepository<'c> {
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone)]
struct UserLookup {
    user_id: Uuid,
    username: String,
    primary_user_email_id: Option<Uuid>,

    #[allow(dead_code)]
    created_at: DateTime<Utc>,
}

impl From<UserLookup> for User {
    fn from(value: UserLookup) -> Self {
        let id = value.user_id.into();
        Self {
            id,
            username: value.username,
            sub: id.to_string(),
            primary_user_email_id: value.primary_user_email_id.map(Into::into),
        }
    }
}

#[async_trait]
impl<'c> UserRepository for PgUserRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        skip_all,
        fields(user.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error> {
        let res = sqlx::query_as!(
            UserLookup,
            r#"
                SELECT user_id
                     , username
                     , primary_user_email_id
                     , created_at
                FROM users
                WHERE user_id = $1
            "#,
            Uuid::from(id),
        )
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error> {
        let res = sqlx::query_as!(
            UserLookup,
            r#"
                SELECT user_id
                     , username
                     , primary_user_email_id
                     , created_at
                FROM users
                WHERE username = $1
            "#,
            username,
        )
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        skip_all,
        fields(
            user.username = username,
            user.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        username: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
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
        .execute(&mut *self.conn)
        .await?;

        Ok(User {
            id,
            username,
            sub: id.to_string(),
            primary_user_email_id: None,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error> {
        let exists = sqlx::query_scalar!(
            r#"
                SELECT EXISTS(
                    SELECT 1 FROM users WHERE username = $1
                ) AS "exists!"
            "#,
            username
        )
        .fetch_one(&mut *self.conn)
        .await?;

        Ok(exists)
    }
}

#[derive(sqlx::FromRow)]
struct SessionLookup {
    user_session_id: Uuid,
    user_session_created_at: DateTime<Utc>,
    user_id: Uuid,
    user_username: String,
    user_primary_user_email_id: Option<Uuid>,
    last_authentication_id: Option<Uuid>,
    last_authd_at: Option<DateTime<Utc>>,
}

impl TryInto<BrowserSession> for SessionLookup {
    type Error = DatabaseInconsistencyError;

    fn try_into(self) -> Result<BrowserSession, Self::Error> {
        let id = Ulid::from(self.user_id);
        let user = User {
            id,
            username: self.user_username,
            sub: id.to_string(),
            primary_user_email_id: self.user_primary_user_email_id.map(Into::into),
        };

        let last_authentication = match (self.last_authentication_id, self.last_authd_at) {
            (Some(id), Some(created_at)) => Some(Authentication {
                id: id.into(),
                created_at,
            }),
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on(
                    "user_session_authentications",
                ))
            }
        };

        Ok(BrowserSession {
            id: self.user_session_id.into(),
            user,
            created_at: self.user_session_created_at,
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
            SELECT s.user_session_id
                 , s.created_at                     AS "user_session_created_at"
                 , u.user_id
                 , u.username                       AS "user_username"
                 , u.primary_user_email_id          AS "user_primary_user_email_id"
                 , a.user_session_authentication_id AS "last_authentication_id?"
                 , a.created_at                     AS "last_authd_at?"
            FROM user_sessions s
            INNER JOIN users u
                USING (user_id)
            LEFT JOIN user_session_authentications a
                USING (user_session_id)
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
