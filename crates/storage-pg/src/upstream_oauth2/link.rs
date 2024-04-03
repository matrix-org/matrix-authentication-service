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
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider, User};
use mas_storage::{
    upstream_oauth2::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
    Clock, Page, Pagination,
};
use rand::RngCore;
use sea_query::{enum_def, Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    iden::{UpstreamOAuthLinks, UpstreamOAuthProviders},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
    DatabaseError,
};

/// An implementation of [`UpstreamOAuthLinkRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthLinkRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthLinkRepository<'c> {
    /// Create a new [`PgUpstreamOAuthLinkRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
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
        .fetch_optional(&mut *self.conn)
        .await?
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
        .fetch_optional(&mut *self.conn)
        .await?
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
        clock: &dyn Clock,
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
        name = "db.upstream_oauth_link.list",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UpstreamOAuthLinkFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthLink>, DatabaseError> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthLinkId,
                )),
                LinkLookupIden::UpstreamOauthLinkId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthProviderId,
                )),
                LinkLookupIden::UpstreamOauthProviderId,
            )
            .expr_as(
                Expr::col((UpstreamOAuthLinks::Table, UpstreamOAuthLinks::UserId)),
                LinkLookupIden::UserId,
            )
            .expr_as(
                Expr::col((UpstreamOAuthLinks::Table, UpstreamOAuthLinks::Subject)),
                LinkLookupIden::Subject,
            )
            .expr_as(
                Expr::col((UpstreamOAuthLinks::Table, UpstreamOAuthLinks::CreatedAt)),
                LinkLookupIden::CreatedAt,
            )
            .from(UpstreamOAuthLinks::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((UpstreamOAuthLinks::Table, UpstreamOAuthLinks::UserId))
                    .eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.provider().map(|provider| {
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthProviderId,
                ))
                .eq(Uuid::from(provider.id))
            }))
            .and_where_option(filter.provider_enabled().map(|enabled| {
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthProviderId,
                ))
                .eq(Expr::any(
                    Query::select()
                        .expr(Expr::col((
                            UpstreamOAuthProviders::Table,
                            UpstreamOAuthProviders::UpstreamOAuthProviderId,
                        )))
                        .from(UpstreamOAuthProviders::Table)
                        .and_where(
                            Expr::col((
                                UpstreamOAuthProviders::Table,
                                UpstreamOAuthProviders::DisabledAt,
                            ))
                            .is_null()
                            .eq(enabled),
                        )
                        .take(),
                ))
            }))
            .generate_pagination(
                (
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthLinkId,
                ),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<LinkLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).map(UpstreamOAuthLink::from);

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.count",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn count(&mut self, filter: UpstreamOAuthLinkFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthLinkId,
                ))
                .count(),
            )
            .from(UpstreamOAuthLinks::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((UpstreamOAuthLinks::Table, UpstreamOAuthLinks::UserId))
                    .eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.provider().map(|provider| {
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthProviderId,
                ))
                .eq(Uuid::from(provider.id))
            }))
            .and_where_option(filter.provider_enabled().map(|enabled| {
                Expr::col((
                    UpstreamOAuthLinks::Table,
                    UpstreamOAuthLinks::UpstreamOAuthProviderId,
                ))
                .eq(Expr::any(
                    Query::select()
                        .expr(Expr::col((
                            UpstreamOAuthProviders::Table,
                            UpstreamOAuthProviders::UpstreamOAuthProviderId,
                        )))
                        .from(UpstreamOAuthProviders::Table)
                        .and_where(
                            Expr::col((
                                UpstreamOAuthProviders::Table,
                                UpstreamOAuthProviders::DisabledAt,
                            ))
                            .is_null()
                            .eq(enabled),
                        )
                        .take(),
                ))
            }))
            .build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }
}
