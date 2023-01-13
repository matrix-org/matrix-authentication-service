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
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider, User};
use rand::RngCore;
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{Page, QueryBuilderExt},
    tracing::ExecuteExt,
    Clock, DatabaseError, LookupResultExt,
};

#[async_trait]
pub trait UpstreamOAuthLinkRepository: Send + Sync {
    type Error;

    /// Lookup an upstream OAuth link by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    /// Find an upstream OAuth link for a provider by its subject
    async fn find_by_subject(
        &mut self,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: &str,
    ) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    /// Add a new upstream OAuth link
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: String,
    ) -> Result<UpstreamOAuthLink, Self::Error>;

    /// Associate an upstream OAuth link to a user
    async fn associate_to_user(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
        user: &User,
    ) -> Result<(), Self::Error>;

    /// Get a paginated list of upstream OAuth links on a user
    async fn list_paginated(
        &mut self,
        user: &User,
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Page<UpstreamOAuthLink>, Self::Error>;
}

pub struct PgUpstreamOAuthLinkRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthLinkRepository<'c> {
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
struct LinkLookup {
    upstream_oauth_link_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    user_id: Option<Uuid>,
    subject: String,
    created_at: DateTime<Utc>,
}

impl From<LinkLookup> for UpstreamOAuthLink {
    fn from(value: LinkLookup) -> Self {
        UpstreamOAuthLink {
            id: Ulid::from(value.upstream_oauth_link_id),
            provider_id: Ulid::from(value.upstream_oauth_provider_id),
            user_id: value.user_id.map(Ulid::from),
            subject: value.subject,
            created_at: value.created_at,
        }
    }
}

#[async_trait]
impl<'c> UpstreamOAuthLinkRepository for PgUpstreamOAuthLinkRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_link.lookup",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_link.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLink>, Self::Error> {
        let res = sqlx::query_as!(
            LinkLookup,
            r#"
                SELECT
                    upstream_oauth_link_id,
                    upstream_oauth_provider_id,
                    user_id,
                    subject,
                    created_at
                FROM upstream_oauth_links
                WHERE upstream_oauth_link_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?
        .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.find_by_subject",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_link.subject = subject,
            %upstream_oauth_provider.id,
            %upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
        ),
        err,
    )]
    async fn find_by_subject(
        &mut self,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: &str,
    ) -> Result<Option<UpstreamOAuthLink>, Self::Error> {
        let res = sqlx::query_as!(
            LinkLookup,
            r#"
                SELECT
                    upstream_oauth_link_id,
                    upstream_oauth_provider_id,
                    user_id,
                    subject,
                    created_at
                FROM upstream_oauth_links
                WHERE upstream_oauth_provider_id = $1
                  AND subject = $2
            "#,
            Uuid::from(upstream_oauth_provider.id),
            subject,
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?
        .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.add",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_link.id,
            upstream_oauth_link.subject = subject,
            %upstream_oauth_provider.id,
            %upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: String,
    ) -> Result<UpstreamOAuthLink, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("upstream_oauth_link.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO upstream_oauth_links (
                    upstream_oauth_link_id,
                    upstream_oauth_provider_id,
                    user_id,
                    subject,
                    created_at
                ) VALUES ($1, $2, NULL, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(upstream_oauth_provider.id),
            &subject,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthLink {
            id,
            provider_id: upstream_oauth_provider.id,
            user_id: None,
            subject,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.associate_to_user",
        skip_all,
        fields(
            db.statement,
            %upstream_oauth_link.id,
            %upstream_oauth_link.subject,
            %user.id,
            %user.username,
        ),
        err,
    )]
    async fn associate_to_user(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
        user: &User,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
                UPDATE upstream_oauth_links
                SET user_id = $1
                WHERE upstream_oauth_link_id = $2
            "#,
            Uuid::from(user.id),
            Uuid::from(upstream_oauth_link.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.list_paginated",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %user.username,
        ),
        err
    )]
    async fn list_paginated(
        &mut self,
        user: &User,
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Page<UpstreamOAuthLink>, Self::Error> {
        let mut query = QueryBuilder::new(
            r#"
                SELECT
                    upstream_oauth_link_id,
                    upstream_oauth_provider_id,
                    user_id,
                    subject,
                    created_at
                FROM upstream_oauth_links
            "#,
        );

        query
            .push(" WHERE user_id = ")
            .push_bind(Uuid::from(user.id))
            .generate_pagination("upstream_oauth_link_id", before, after, first, last)?;

        let edges: Vec<LinkLookup> = query
            .build_query_as()
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = Page::process(edges, first, last)?.map(UpstreamOAuthLink::from);
        Ok(page)
    }
}
