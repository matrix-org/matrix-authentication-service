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
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider};
use rand::Rng;
use sqlx::PgExecutor;
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, GenericLookupError};

struct LinkLookup {
    upstream_oauth_link_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    user_id: Option<Uuid>,
    subject: String,
    created_at: DateTime<Utc>,
}

#[tracing::instrument(
    skip_all,
    fields(upstream_oauth_link.id = %id),
    err,
)]
pub async fn lookup_link(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<(UpstreamOAuthLink, Ulid, Option<Ulid>), GenericLookupError> {
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
    .map_err(GenericLookupError::what("Upstream OAuth 2.0 link"))?;

    Ok((
        UpstreamOAuthLink {
            id: Ulid::from(res.upstream_oauth_link_id),
            subject: res.subject,
            created_at: res.created_at,
        },
        Ulid::from(res.upstream_oauth_provider_id),
        res.user_id.map(Ulid::from),
    ))
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
) -> Result<(UpstreamOAuthLink, Option<Ulid>), GenericLookupError> {
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
    .map_err(GenericLookupError::what("Upstream OAuth 2.0 link"))?;

    Ok((
        UpstreamOAuthLink {
            id: Ulid::from(res.upstream_oauth_link_id),
            subject: res.subject,
            created_at: res.created_at,
        },
        res.user_id.map(Ulid::from),
    ))
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
) -> Result<UpstreamOAuthLink, sqlx::Error> {
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
        subject,
        created_at,
    })
}
