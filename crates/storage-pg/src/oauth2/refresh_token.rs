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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{AccessToken, RefreshToken, RefreshTokenState, Session};
use mas_storage::{oauth2::OAuth2RefreshTokenRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError};

/// An implementation of [`OAuth2RefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2RefreshTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2RefreshTokenRepository<'c> {
    /// Create a new [`PgOAuth2RefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2RefreshTokenLookup {
    oauth2_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    oauth2_access_token_id: Option<Uuid>,
    oauth2_session_id: Uuid,
}

impl From<OAuth2RefreshTokenLookup> for RefreshToken {
    fn from(value: OAuth2RefreshTokenLookup) -> Self {
        let state = match value.consumed_at {
            None => RefreshTokenState::Valid,
            Some(consumed_at) => RefreshTokenState::Consumed { consumed_at },
        };

        RefreshToken {
            id: value.oauth2_refresh_token_id.into(),
            state,
            session_id: value.oauth2_session_id.into(),
            refresh_token: value.refresh_token,
            created_at: value.created_at,
            access_token_id: value.oauth2_access_token_id.map(Ulid::from),
        }
    }
}

#[async_trait]
impl<'c> OAuth2RefreshTokenRepository for PgOAuth2RefreshTokenRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.lookup",
        skip_all,
        fields(
            db.statement,
            refresh_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2RefreshTokenLookup,
            r#"
                SELECT oauth2_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , oauth2_access_token_id
                     , oauth2_session_id
                FROM oauth2_refresh_tokens

                WHERE oauth2_refresh_token_id = $1
            "#,
            Uuid::from(id),
        )
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.find_by_token",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2RefreshTokenLookup,
            r#"
                SELECT oauth2_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , oauth2_access_token_id
                     , oauth2_session_id
                FROM oauth2_refresh_tokens

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
        name = "db.oauth2_refresh_token.add",
        skip_all,
        fields(
            db.statement,
            %session.id,
            user.id = %session.user_id,
            client.id = %session.client_id,
            refresh_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("refresh_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_refresh_tokens
                    (oauth2_refresh_token_id, oauth2_session_id, oauth2_access_token_id,
                     refresh_token, created_at)
                VALUES
                    ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            Uuid::from(access_token.id),
            refresh_token,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(RefreshToken {
            id,
            state: RefreshTokenState::default(),
            session_id: session.id,
            refresh_token,
            access_token_id: Some(access_token.id),
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.consume",
        skip_all,
        fields(
            db.statement,
            %refresh_token.id,
            session.id = %refresh_token.session_id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error> {
        let consumed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_refresh_tokens
                SET consumed_at = $2
                WHERE oauth2_refresh_token_id = $1
            "#,
            Uuid::from(refresh_token.id),
            consumed_at,
        )
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        refresh_token
            .consume(consumed_at)
            .map_err(DatabaseError::to_invalid_operation)
    }
}
