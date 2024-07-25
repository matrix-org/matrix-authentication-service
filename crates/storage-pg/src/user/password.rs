// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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
use mas_data_model::{Password, User};
use mas_storage::{user::UserPasswordRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`UserPasswordRepository`] for a PostgreSQL connection
pub struct PgUserPasswordRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserPasswordRepository<'c> {
    /// Create a new [`PgUserPasswordRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct UserPasswordLookup {
    user_password_id: Uuid,
    hashed_password: String,
    version: i32,
    upgraded_from_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl<'c> UserPasswordRepository for PgUserPasswordRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_password.active",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            %user.username,
        ),
        err,
    )]
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasswordLookup,
            r#"
                SELECT up.user_password_id
                     , up.hashed_password
                     , up.version
                     , up.upgraded_from_id
                     , up.created_at
                FROM user_passwords up
                WHERE up.user_id = $1
                ORDER BY up.created_at DESC
                LIMIT 1
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        let id = Ulid::from(res.user_password_id);

        let version = res.version.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("user_passwords")
                .column("version")
                .row(id)
                .source(e)
        })?;

        let upgraded_from_id = res.upgraded_from_id.map(Ulid::from);
        let created_at = res.created_at;
        let hashed_password = res.hashed_password;

        Ok(Some(Password {
            id,
            hashed_password,
            version,
            upgraded_from_id,
            created_at,
        }))
    }

    #[tracing::instrument(
        name = "db.user_password.add",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            %user.username,
            user_password.id,
            user_password.version = version,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_password.id", tracing::field::display(id));

        let upgraded_from_id = upgraded_from.map(|p| p.id);

        sqlx::query!(
            r#"
                INSERT INTO user_passwords
                    (user_password_id, user_id, hashed_password, version, upgraded_from_id, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            hashed_password,
            i32::from(version),
            upgraded_from_id.map(Uuid::from),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Password {
            id,
            hashed_password,
            version,
            upgraded_from_id,
            created_at,
        })
    }
}
