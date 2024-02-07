// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::User;
use mas_storage::{user::UserRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError};

mod email;
mod password;
mod session;
mod terms;

#[cfg(test)]
mod tests;

pub use self::{
    email::PgUserEmailRepository, password::PgUserPasswordRepository,
    session::PgBrowserSessionRepository, terms::PgUserTermsRepository,
};

/// An implementation of [`UserRepository`] for a PostgreSQL connection
pub struct PgUserRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRepository<'c> {
    /// Create a new [`PgUserRepository`] from an active PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone)]
struct UserLookup {
    user_id: Uuid,
    username: String,
    primary_user_email_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    locked_at: Option<DateTime<Utc>>,
    can_request_admin: bool,
}

impl From<UserLookup> for User {
    fn from(value: UserLookup) -> Self {
        let id = value.user_id.into();
        Self {
            id,
            username: value.username,
            sub: id.to_string(),
            primary_user_email_id: value.primary_user_email_id.map(Into::into),
            created_at: value.created_at,
            locked_at: value.locked_at,
            can_request_admin: value.can_request_admin,
        }
    }
}

#[async_trait]
impl<'c> UserRepository for PgUserRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user.lookup",
        skip_all,
        fields(
            db.statement,
            user.id = %id,
        ),
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
                     , locked_at
                     , can_request_admin
                FROM users
                WHERE user_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.user.find_by_username",
        skip_all,
        fields(
            db.statement,
            user.username = username,
        ),
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
                     , locked_at
                     , can_request_admin
                FROM users
                WHERE username = $1
            "#,
            username,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.user.add",
        skip_all,
        fields(
            db.statement,
            user.username = username,
            user.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user.id", tracing::field::display(id));

        let res = sqlx::query!(
            r#"
                INSERT INTO users (user_id, username, created_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (username) DO NOTHING
            "#,
            Uuid::from(id),
            username,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // If the user already exists, want to return an error but not poison the
        // transaction
        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(User {
            id,
            username,
            sub: id.to_string(),
            primary_user_email_id: None,
            created_at,
            locked_at: None,
            can_request_admin: false,
        })
    }

    #[tracing::instrument(
        name = "db.user.exists",
        skip_all,
        fields(
            db.statement,
            user.username = username,
        ),
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
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        Ok(exists)
    }

    #[tracing::instrument(
        name = "db.user.lock",
        skip_all,
        fields(
            db.statement,
            %user.id,
        ),
        err,
    )]
    async fn lock(&mut self, clock: &dyn Clock, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_some() {
            return Ok(user);
        }

        let locked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE users
                SET locked_at = $1
                WHERE user_id = $2
            "#,
            locked_at,
            Uuid::from(user.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.locked_at = Some(locked_at);

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(
            db.statement,
            %user.id,
        ),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_none() {
            return Ok(user);
        }

        let res = sqlx::query!(
            r#"
                UPDATE users
                SET locked_at = NULL
                WHERE user_id = $1
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.locked_at = None;

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.set_can_request_admin",
        skip_all,
        fields(
            db.statement,
            %user.id,
            user.can_request_admin = can_request_admin,
        ),
        err,
    )]
    async fn set_can_request_admin(
        &mut self,
        mut user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE users
                SET can_request_admin = $2
                WHERE user_id = $1
            "#,
            Uuid::from(user.id),
            can_request_admin,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.can_request_admin = can_request_admin;

        Ok(user)
    }
}
