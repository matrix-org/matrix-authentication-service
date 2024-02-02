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
use mas_data_model::{BrowserSession, DeviceCodeGrant, DeviceCodeGrantState, Session};
use mas_storage::{
    oauth2::{OAuth2DeviceCodeGrantParams, OAuth2DeviceCodeGrantRepository},
    Clock,
};
use oauth2_types::scope::Scope;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{errors::DatabaseInconsistencyError, DatabaseError, ExecuteExt};

/// An implementation of [`OAuth2DeviceCodeGrantRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2DeviceCodeGrantRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2DeviceCodeGrantRepository<'c> {
    /// Create a new [`PgOAuth2DeviceCodeGrantRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2DeviceGrantLookup {
    oauth2_device_code_grant_id: Uuid,
    oauth2_client_id: Uuid,
    scope: String,
    device_code: String,
    user_code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    user_session_id: Option<Uuid>,
    oauth2_session_id: Option<Uuid>,
}

impl TryFrom<OAuth2DeviceGrantLookup> for DeviceCodeGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(
        OAuth2DeviceGrantLookup {
            oauth2_device_code_grant_id,
            oauth2_client_id,
            scope,
            device_code,
            user_code,
            created_at,
            expires_at,
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth2_session_id,
        }: OAuth2DeviceGrantLookup,
    ) -> Result<Self, Self::Error> {
        let id = Ulid::from(oauth2_device_code_grant_id);
        let client_id = Ulid::from(oauth2_client_id);

        let scope: Scope = scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match (
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth2_session_id,
        ) {
            (None, None, None, None, None) => DeviceCodeGrantState::Pending,

            (Some(fulfilled_at), None, None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Fulfilled {
                    browser_session_id: Ulid::from(user_session_id),
                    fulfilled_at,
                }
            }

            (None, Some(rejected_at), None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Rejected {
                    browser_session_id: Ulid::from(user_session_id),
                    rejected_at,
                }
            }

            (
                Some(fulfilled_at),
                None,
                Some(exchanged_at),
                Some(user_session_id),
                Some(oauth2_session_id),
            ) => DeviceCodeGrantState::Exchanged {
                browser_session_id: Ulid::from(user_session_id),
                session_id: Ulid::from(oauth2_session_id),
                fulfilled_at,
                exchanged_at,
            },

            _ => return Err(DatabaseInconsistencyError::on("oauth2_device_code_grant").row(id)),
        };

        Ok(DeviceCodeGrant {
            id,
            state,
            client_id,
            scope,
            user_code,
            device_code,
            created_at,
            expires_at,
        })
    }
}

#[async_trait]
impl<'c> OAuth2DeviceCodeGrantRepository for PgOAuth2DeviceCodeGrantRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.add",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.id,
            oauth2_device_code.scope = %params.scope,
            oauth2_client.id = %params.client.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: OAuth2DeviceCodeGrantParams<'_>,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("oauth2_device_code.id", tracing::field::display(id));

        let created_at = now;
        let expires_at = now + params.expires_in;
        let client_id = params.client.id;

        sqlx::query!(
            r#"
                INSERT INTO "oauth2_device_code_grant" 
                    ( oauth2_device_code_grant_id
                    , oauth2_client_id
                    , scope
                    , device_code
                    , user_code
                    , created_at
                    , expires_at
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::from(id),
            Uuid::from(client_id),
            params.scope.to_string(),
            &params.device_code,
            &params.user_code,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(DeviceCodeGrant {
            id,
            state: DeviceCodeGrantState::Pending,
            client_id,
            scope: params.scope,
            user_code: params.user_code,
            device_code: params.device_code,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.lookup",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                FROM 
                    oauth2_device_code_grant

                WHERE oauth2_device_code_grant_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.find_by_user_code",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.user_code = %user_code,
        ),
        err,
    )]
    async fn find_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                FROM 
                    oauth2_device_code_grant

                WHERE user_code = $1
            "#,
            user_code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.find_by_device_code",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.device_code = %device_code,
        ),
        err,
    )]
    async fn find_by_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                FROM 
                    oauth2_device_code_grant

                WHERE device_code = $1
            "#,
            device_code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.fulfill",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .fulfill(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET fulfilled_at = $1
                  , user_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            fulfilled_at,
            Uuid::from(browser_session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.reject",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn reject(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .reject(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET rejected_at = $1
                  , user_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            fulfilled_at,
            Uuid::from(browser_session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.exchange",
        skip_all,
        fields(
            db.statement,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            oauth2_session.id = %session.id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        session: &Session,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let exchanged_at = clock.now();
        let device_code_grant = device_code_grant
            .exchange(session, exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET exchanged_at = $1
                  , oauth2_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            exchanged_at,
            Uuid::from(session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }
}
