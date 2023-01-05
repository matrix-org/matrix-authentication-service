// Copyright 2022 The Matrix.org Foundation C.I.C.
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
use mas_data_model::{AuthorizationGrant, BrowserSession, Session, User};
use rand::RngCore;
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{process_page, Page, QueryBuilderExt},
    tracing::ExecuteExt,
    Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt,
};

#[async_trait]
pub trait OAuth2SessionRepository {
    type Error;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error>;

    async fn create_from_grant(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        grant: &AuthorizationGrant,
        user_session: &BrowserSession,
    ) -> Result<Session, Self::Error>;

    async fn finish(&mut self, clock: &Clock, session: Session) -> Result<Session, Self::Error>;

    async fn list_paginated(
        &mut self,
        user: &User,
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Page<Session>, Self::Error>;
}

pub struct PgOAuth2SessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2SessionRepository<'c> {
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

        Ok(Session {
            id,
            client_id: value.oauth2_client_id.into(),
            user_session_id: value.user_session_id.into(),
            scope,
            finished_at: value.finished_at,
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
            client.id = %grant.client.id,
            session.id,
            session.scope = %grant.scope,
        ),
        err,
    )]
    async fn create_from_grant(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
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
            Uuid::from(grant.client.id),
            grant.scope.to_string(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Session {
            id,
            user_session_id: user_session.id,
            client_id: grant.client.id,
            scope: grant.scope.clone(),
            finished_at: None,
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
        clock: &Clock,
        mut session: Session,
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

        session.finished_at = Some(finished_at);

        Ok(session)
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
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Page<Session>, Self::Error> {
        let mut query = QueryBuilder::new(
            r#"
                SELECT oauth2_session_id
                     , user_session_id
                     , oauth2_client_id
                     , scope
                     , created_at
                     , finished_at
                FROM oauth2_sessions os
            "#,
        );

        query
            .push(" WHERE us.user_id = ")
            .push_bind(Uuid::from(user.id))
            .generate_pagination("oauth2_session_id", before, after, first, last)?;

        let edges: Vec<OAuthSessionLookup> = query
            .build_query_as()
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let (has_previous_page, has_next_page, edges) = process_page(edges, first, last)?;

        let edges: Result<Vec<_>, DatabaseInconsistencyError> =
            edges.into_iter().map(Session::try_from).collect();

        Ok(Page {
            has_next_page,
            has_previous_page,
            edges: edges?,
        })
    }
}
