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
use mas_data_model::{UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProvider};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, Clock, DatabaseError, LookupResultExt};

#[async_trait]
pub trait UpstreamOAuthSessionRepository: Send + Sync {
    type Error;

    /// Lookup a session by its ID
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error>;

    /// Add a session to the database
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state: String,
        code_challenge_verifier: Option<String>,
        nonce: String,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as completed and associate the given link
    async fn complete_with_link(
        &mut self,
        clock: &Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as consumed
    async fn consume(
        &mut self,
        clock: &Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;
}

pub struct PgUpstreamOAuthSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthSessionRepository<'c> {
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct SessionLookup {
    upstream_oauth_authorization_session_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    upstream_oauth_link_id: Option<Uuid>,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: String,
    id_token: Option<String>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl<'c> UpstreamOAuthSessionRepository for PgUpstreamOAuthSessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.lookup",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error> {
        let res = sqlx::query_as!(
            SessionLookup,
            r#"
                SELECT
                    upstream_oauth_authorization_session_id,
                    upstream_oauth_provider_id,
                    upstream_oauth_link_id,
                    state,
                    code_challenge_verifier,
                    nonce,
                    id_token,
                    created_at,
                    completed_at,
                    consumed_at
                FROM upstream_oauth_authorization_sessions
                WHERE upstream_oauth_authorization_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(res) = res else { return Ok(None) };

        let session = UpstreamOAuthAuthorizationSession {
            id: res.upstream_oauth_authorization_session_id.into(),
            provider_id: res.upstream_oauth_provider_id.into(),
            link_id: res.upstream_oauth_link_id.map(Ulid::from),
            state: res.state,
            code_challenge_verifier: res.code_challenge_verifier,
            nonce: res.nonce,
            id_token: res.id_token,
            created_at: res.created_at,
            completed_at: res.completed_at,
            consumed_at: res.consumed_at,
        };

        Ok(Some(session))
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.add",
        skip_all,
        fields(
            db.statement,
            %upstream_oauth_provider.id,
            %upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
            upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state: String,
        code_challenge_verifier: Option<String>,
        nonce: String,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "upstream_oauth_authorization_session.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO upstream_oauth_authorization_sessions (
                    upstream_oauth_authorization_session_id,
                    upstream_oauth_provider_id,
                    state,
                    code_challenge_verifier,
                    nonce,
                    created_at,
                    completed_at,
                    consumed_at,
                    id_token
                ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL)
            "#,
            Uuid::from(id),
            Uuid::from(upstream_oauth_provider.id),
            &state,
            code_challenge_verifier.as_deref(),
            nonce,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthAuthorizationSession {
            id,
            provider_id: upstream_oauth_provider.id,
            link_id: None,
            state,
            code_challenge_verifier,
            nonce,
            id_token: None,
            created_at,
            completed_at: None,
            consumed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.complete_with_link",
        skip_all,
        fields(
            db.statement,
            %upstream_oauth_authorization_session.id,
            %upstream_oauth_link.id,
        ),
        err,
    )]
    async fn complete_with_link(
        &mut self,
        clock: &Clock,
        mut upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let completed_at = clock.now();
        sqlx::query!(
            r#"
                UPDATE upstream_oauth_authorization_sessions
                SET upstream_oauth_link_id = $1,
                    completed_at = $2,
                    id_token = $3
                WHERE upstream_oauth_authorization_session_id = $4
            "#,
            Uuid::from(upstream_oauth_link.id),
            completed_at,
            id_token,
            Uuid::from(upstream_oauth_authorization_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        upstream_oauth_authorization_session.completed_at = Some(completed_at);
        upstream_oauth_authorization_session.id_token = id_token;
        upstream_oauth_authorization_session.link_id = Some(upstream_oauth_link.id);

        Ok(upstream_oauth_authorization_session)
    }

    /// Mark a session as consumed
    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.consume",
        skip_all,
        fields(
            db.statement,
            %upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &Clock,
        mut upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let consumed_at = clock.now();
        sqlx::query!(
            r#"
                UPDATE upstream_oauth_authorization_sessions
                SET consumed_at = $1
                WHERE upstream_oauth_authorization_session_id = $2
            "#,
            consumed_at,
            Uuid::from(upstream_oauth_authorization_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        upstream_oauth_authorization_session.consumed_at = Some(consumed_at);

        Ok(upstream_oauth_authorization_session)
    }
}
