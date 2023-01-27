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
use mas_data_model::{AuthorizationGrant, BrowserSession, Session, SessionState, User};
use mas_storage::{oauth2::OAuth2SessionRepository, Clock, Page, Pagination};
use rand::RngCore;
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::QueryBuilderExt, tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError,
    LookupResultExt,
};

/// An implementation of [`OAuth2SessionRepository`] for a PostgreSQL connection
pub struct PgOAuth2SessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2SessionRepository<'c> {
    /// Create a new [`PgOAuth2SessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
struct OAuthSessionLookup {
    oauth2_session_id: Uuid,
    user_session_id: Uuid,
    oauth2_client_id: Uuid,
    scope: String,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

impl TryFrom<OAuthSessionLookup> for Session {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuthSessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.oauth2_session_id);
        let scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => SessionState::Valid,
            Some(finished_at) => SessionState::Finished { finished_at },
        };

        Ok(Session {
            id,
            state,
            created_at: value.created_at,
            client_id: value.oauth2_client_id.into(),
            user_session_id: value.user_session_id.into(),
            scope,
        })
    }
}

#[async_trait]
impl<'c> OAuth2SessionRepository for PgOAuth2SessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_session.lookup",
        skip_all,
        fields(
            db.statement,
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error> {
        let res = sqlx::query_as!(
            OAuthSessionLookup,
            r#"
                SELECT oauth2_session_id
                     , user_session_id
                     , oauth2_client_id
                     , scope
                     , created_at
                     , finished_at
                FROM oauth2_sessions

                WHERE oauth2_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_session.create_from_grant",
        skip_all,
        fields(
            db.statement,
            %user_session.id,
            user.id = %user_session.user.id,
            %grant.id,
            client.id = %grant.client_id,
            session.id,
            session.scope = %grant.scope,
        ),
        err,
    )]
    async fn create_from_grant(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        grant: &AuthorizationGrant,
        user_session: &BrowserSession,
    ) -> Result<Session, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_sessions
                    ( oauth2_session_id
                    , user_session_id
                    , oauth2_client_id
                    , scope
                    , created_at
                    )
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user_session.id),
            Uuid::from(grant.client_id),
            grant.scope.to_string(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Session {
            id,
            state: SessionState::Valid,
            created_at,
            user_session_id: user_session.id,
            client_id: grant.client_id,
            scope: grant.scope.clone(),
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_session.finish",
        skip_all,
        fields(
            db.statement,
            %session.id,
            %session.scope,
            user_session.id = %session.user_session_id,
            client.id = %session.client_id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        session: Session,
    ) -> Result<Session, Self::Error> {
        let finished_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_sessions
                SET finished_at = $2
                WHERE oauth2_session_id = $1
            "#,
            Uuid::from(session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.list_paginated",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %user.username,
        ),
        err,
    )]
    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error> {
        let mut query = QueryBuilder::new(
            r#"
                SELECT oauth2_session_id
                     , user_session_id
                     , oauth2_client_id
                     , scope
                     , os.created_at
                     , os.finished_at
                FROM oauth2_sessions os
                INNER JOIN user_sessions USING (user_session_id)
            "#,
        );

        query
            .push(" WHERE user_id = ")
            .push_bind(Uuid::from(user.id))
            .generate_pagination("oauth2_session_id", pagination);

        let edges: Vec<OAuthSessionLookup> = query
            .build_query_as()
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(Session::try_from)?;
        Ok(page)
    }
}
