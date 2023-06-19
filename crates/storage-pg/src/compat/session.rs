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
use mas_data_model::{CompatSession, CompatSessionState, Device, User};
use mas_storage::{compat::CompatSessionRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError, LookupResultExt};

/// An implementation of [`CompatSessionRepository`] for a PostgreSQL connection
pub struct PgCompatSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatSessionRepository<'c> {
    /// Create a new [`PgCompatSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatSessionLookup {
    compat_session_id: Uuid,
    device_id: String,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    is_synapse_admin: bool,
}

impl TryFrom<CompatSessionLookup> for CompatSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CompatSessionLookup) -> Result<Self, Self::Error> {
        let id = value.compat_session_id.into();
        let device = Device::try_from(value.device_id).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sessions")
                .column("device_id")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => CompatSessionState::Valid,
            Some(finished_at) => CompatSessionState::Finished { finished_at },
        };

        let session = CompatSession {
            id,
            state,
            user_id: value.user_id.into(),
            device,
            created_at: value.created_at,
            is_synapse_admin: value.is_synapse_admin,
        };

        Ok(session)
    }
}

#[async_trait]
impl<'c> CompatSessionRepository for PgCompatSessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_session.lookup",
        skip_all,
        fields(
            db.statement,
            compat_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSessionLookup,
            r#"
                SELECT compat_session_id
                     , device_id
                     , user_id
                     , created_at
                     , finished_at
                     , is_synapse_admin
                FROM compat_sessions
                WHERE compat_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_session.add",
        skip_all,
        fields(
            db.statement,
            compat_session.id,
            %user.id,
            %user.username,
            compat_session.device.id = device.as_str(),
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        is_synapse_admin: bool,
    ) -> Result<CompatSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_sessions (compat_session_id, user_id, device_id, created_at, is_synapse_admin)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            device.as_str(),
            created_at,
            is_synapse_admin,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatSession {
            id,
            state: CompatSessionState::default(),
            user_id: user.id,
            device,
            created_at,
            is_synapse_admin,
        })
    }

    #[tracing::instrument(
        name = "db.compat_session.finish",
        skip_all,
        fields(
            db.statement,
            %compat_session.id,
            user.id = %compat_session.user_id,
            compat_session.device.id = compat_session.device.as_str(),
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error> {
        let finished_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE compat_sessions cs
                SET finished_at = $2
                WHERE compat_session_id = $1
            "#,
            Uuid::from(compat_session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        let compat_session = compat_session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(compat_session)
    }
}
