// Copyright 2023 The Matrix.org Foundation C.I.C.
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
use mas_data_model::{
    CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
};
use mas_storage::{compat::CompatRefreshTokenRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError};

/// An implementation of [`CompatRefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgCompatRefreshTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatRefreshTokenRepository<'c> {
    /// Create a new [`PgCompatRefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatRefreshTokenLookup {
    compat_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    compat_access_token_id: Uuid,
    compat_session_id: Uuid,
}

impl From<CompatRefreshTokenLookup> for CompatRefreshToken {
    fn from(value: CompatRefreshTokenLookup) -> Self {
        let state = match value.consumed_at {
            Some(consumed_at) => CompatRefreshTokenState::Consumed { consumed_at },
            None => CompatRefreshTokenState::Valid,
        };

        Self {
            id: value.compat_refresh_token_id.into(),
            state,
            session_id: value.compat_session_id.into(),
            token: value.refresh_token,
            created_at: value.created_at,
            access_token_id: value.compat_access_token_id.into(),
        }
    }
}

#[async_trait]
impl<'c> CompatRefreshTokenRepository for PgCompatRefreshTokenRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_refresh_token.lookup",
        skip_all,
        fields(
            db.statement,
            compat_refresh_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatRefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatRefreshTokenLookup,
            r#"
                SELECT compat_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , compat_session_id
                     , compat_access_token_id

                FROM compat_refresh_tokens

                WHERE compat_refresh_token_id = $1
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
        name = "db.compat_refresh_token.find_by_token",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<CompatRefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatRefreshTokenLookup,
            r#"
                SELECT compat_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , compat_session_id
                     , compat_access_token_id

                FROM compat_refresh_tokens

                WHERE refresh_token = $1
            "#,
            refresh_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.compat_refresh_token.add",
        skip_all,
        fields(
            db.statement,
            compat_refresh_token.id,
            %compat_session.id,
            user.id = %compat_session.user_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        compat_access_token: &CompatAccessToken,
        token: String,
    ) -> Result<CompatRefreshToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_refresh_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_refresh_tokens
                    (compat_refresh_token_id, compat_session_id,
                     compat_access_token_id, refresh_token, created_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(compat_session.id),
            Uuid::from(compat_access_token.id),
            token,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatRefreshToken {
            id,
            state: CompatRefreshTokenState::default(),
            session_id: compat_session.id,
            access_token_id: compat_access_token.id,
            token,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.compat_refresh_token.consume",
        skip_all,
        fields(
            db.statement,
            %compat_refresh_token.id,
            compat_session.id = %compat_refresh_token.session_id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        compat_refresh_token: CompatRefreshToken,
    ) -> Result<CompatRefreshToken, Self::Error> {
        let consumed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE compat_refresh_tokens
                SET consumed_at = $2
                WHERE compat_refresh_token_id = $1
            "#,
            Uuid::from(compat_refresh_token.id),
            consumed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        let compat_refresh_token = compat_refresh_token
            .consume(consumed_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(compat_refresh_token)
    }
}
