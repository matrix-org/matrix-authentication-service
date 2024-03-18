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
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, AccessTokenState, Session};
use mas_storage::{oauth2::OAuth2AccessTokenRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError};

/// An implementation of [`OAuth2AccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2AccessTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2AccessTokenRepository<'c> {
    /// Create a new [`PgOAuth2AccessTokenRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2AccessTokenLookup {
    oauth2_access_token_id: Uuid,
    oauth2_session_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<OAuth2AccessTokenLookup> for AccessToken {
    fn from(value: OAuth2AccessTokenLookup) -> Self {
        let state = match value.revoked_at {
            None => AccessTokenState::Valid,
            Some(revoked_at) => AccessTokenState::Revoked { revoked_at },
        };

        Self {
            id: value.oauth2_access_token_id.into(),
            state,
            session_id: value.oauth2_session_id.into(),
            access_token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[async_trait]
impl<'c> OAuth2AccessTokenRepository for PgOAuth2AccessTokenRepository<'c> {
    type Error = DatabaseError;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2AccessTokenLookup,
            r#"
                SELECT oauth2_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , revoked_at
                     , oauth2_session_id

                FROM oauth2_access_tokens

                WHERE oauth2_access_token_id = $1
            "#,
            Uuid::from(id),
        )
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.find_by_token",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<AccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2AccessTokenLookup,
            r#"
                SELECT oauth2_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , revoked_at
                     , oauth2_session_id

                FROM oauth2_access_tokens

                WHERE access_token = $1
            "#,
            access_token,
        )
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.add",
        skip_all,
        fields(
            db.statement,
            %session.id,
            client.id = %session.client_id,
            access_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: String,
        expires_after: Option<Duration>,
    ) -> Result<AccessToken, Self::Error> {
        let created_at = clock.now();
        let expires_at = expires_after.map(|d| created_at + d);
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);

        tracing::Span::current().record("access_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_access_tokens
                    (oauth2_access_token_id, oauth2_session_id, access_token, created_at, expires_at)
                VALUES
                    ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            &access_token,
            created_at,
            expires_at,
        )
            .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(AccessToken {
            id,
            state: AccessTokenState::default(),
            access_token,
            session_id: session.id,
            created_at,
            expires_at,
        })
    }

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_access_tokens
                SET revoked_at = $2
                WHERE oauth2_access_token_id = $1
            "#,
            Uuid::from(access_token.id),
            revoked_at,
        )
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        access_token
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    async fn cleanup_expired(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        // Cleanup token which expired more than 15 minutes ago
        let threshold = clock.now() - Duration::microseconds(15 * 60 * 1000 * 1000);
        let res = sqlx::query!(
            r#"
                DELETE FROM oauth2_access_tokens
                WHERE expires_at < $1
            "#,
            threshold,
        )
        .execute(&mut *self.conn)
        .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }
}
