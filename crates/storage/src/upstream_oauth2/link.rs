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

use chrono::{DateTime, Utc};
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider, User};
use rand::Rng;
use sqlx::{PgExecutor, QueryBuilder};
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    Clock, DatabaseError, LookupResultExt,
};

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

#[tracing::instrument(
    skip_all,
    fields(upstream_oauth_link.id = %id),
    err,
)]
pub async fn lookup_link(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<Option<UpstreamOAuthLink>, DatabaseError> {
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
    .fetch_one(executor)
    .await
    .to_option()?
    .map(Into::into);

    Ok(res)
}

#[tracing::instrument(
    skip_all,
    fields(
        upstream_oauth_link.subject = subject,
        %upstream_oauth_provider.id,
        %upstream_oauth_provider.issuer,
        %upstream_oauth_provider.client_id,
    ),
    err,
)]
pub async fn lookup_link_by_subject(
    executor: impl PgExecutor<'_>,
    upstream_oauth_provider: &UpstreamOAuthProvider,
    subject: &str,
) -> Result<Option<UpstreamOAuthLink>, DatabaseError> {
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
    .fetch_one(executor)
    .await
    .to_option()?
    .map(Into::into);

    Ok(res)
}

#[tracing::instrument(
    skip_all,
    fields(
        upstream_oauth_link.id,
        upstream_oauth_link.subject = subject,
        %upstream_oauth_provider.id,
        %upstream_oauth_provider.issuer,
        %upstream_oauth_provider.client_id,
    ),
    err,
)]
pub async fn add_link(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    upstream_oauth_provider: &UpstreamOAuthProvider,
    subject: String,
) -> Result<UpstreamOAuthLink, DatabaseError> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
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
    .execute(executor)
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
    skip_all,
    fields(
        %upstream_oauth_link.id,
        %upstream_oauth_link.subject,
        %user.id,
        %user.username,
    ),
    err,
)]
pub async fn associate_link_to_user(
    executor: impl PgExecutor<'_>,
    upstream_oauth_link: &UpstreamOAuthLink,
    user: &User,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE upstream_oauth_links
            SET user_id = $1
            WHERE upstream_oauth_link_id = $2
        "#,
        Uuid::from(user.id),
        Uuid::from(upstream_oauth_link.id),
    )
    .execute(executor)
    .await?;

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(%user.id, %user.username),
    err(Display)
)]
pub async fn get_paginated_user_links(
    executor: impl PgExecutor<'_>,
    user: &User,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<UpstreamOAuthLink>), DatabaseError> {
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

    let span = info_span!(
        "Fetch paginated upstream OAuth 2.0 user links",
        db.statement = query.sql()
    );
    let page: Vec<LinkLookup> = query
        .build_query_as()
        .fetch_all(executor)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let page: Vec<_> = page.into_iter().map(Into::into).collect();
    Ok((has_previous_page, has_next_page, page))
}
