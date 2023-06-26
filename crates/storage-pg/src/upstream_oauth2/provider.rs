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
use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, Clock, Page, Pagination};
use oauth2_types::scope::Scope;
use rand::RngCore;
use sqlx::{types::Json, PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::QueryBuilderExt, tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError,
    LookupResultExt,
};

/// An implementation of [`UpstreamOAuthProviderRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthProviderRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthProviderRepository<'c> {
    /// Create a new [`PgUpstreamOAuthProviderRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
struct ProviderLookup {
    upstream_oauth_provider_id: Uuid,
    issuer: String,
    scope: String,
    client_id: String,
    encrypted_client_secret: Option<String>,
    token_endpoint_signing_alg: Option<String>,
    token_endpoint_auth_method: String,
    created_at: DateTime<Utc>,
    claims_imports: Json<UpstreamOAuthProviderClaimsImports>,
}

impl TryFrom<ProviderLookup> for UpstreamOAuthProvider {
    type Error = DatabaseInconsistencyError;
    fn try_from(value: ProviderLookup) -> Result<Self, Self::Error> {
        let id = value.upstream_oauth_provider_id.into();
        let scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("scope")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_auth_method = value.token_endpoint_auth_method.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("token_endpoint_auth_method")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_signing_alg = value
            .token_endpoint_signing_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("token_endpoint_signing_alg")
                    .row(id)
                    .source(e)
            })?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer: value.issuer,
            scope,
            client_id: value.client_id,
            encrypted_client_secret: value.encrypted_client_secret,
            token_endpoint_auth_method,
            token_endpoint_signing_alg,
            created_at: value.created_at,
            claims_imports: value.claims_imports.0,
        })
    }
}

#[async_trait]
impl<'c> UpstreamOAuthProviderRepository for PgUpstreamOAuthProviderRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.lookup",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error> {
        let res = sqlx::query_as!(
            ProviderLookup,
            r#"
                SELECT
                    upstream_oauth_provider_id,
                    issuer,
                    scope,
                    client_id,
                    encrypted_client_secret,
                    token_endpoint_signing_alg,
                    token_endpoint_auth_method,
                    created_at,
                    claims_imports as "claims_imports: Json<UpstreamOAuthProviderClaimsImports>"
                FROM upstream_oauth_providers
                WHERE upstream_oauth_provider_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let res = res
            .map(UpstreamOAuthProvider::try_from)
            .transpose()
            .map_err(DatabaseError::from)?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.add",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_provider.id,
            upstream_oauth_provider.issuer = %issuer,
            upstream_oauth_provider.client_id = %client_id,
        ),
        err,
    )]
    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        issuer: String,
        scope: Scope,
        token_endpoint_auth_method: OAuthClientAuthenticationMethod,
        token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
        client_id: String,
        encrypted_client_secret: Option<String>,
        claims_imports: UpstreamOAuthProviderClaimsImports,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("upstream_oauth_provider.id", tracing::field::display(id));

        sqlx::query!(
            r#"
            INSERT INTO upstream_oauth_providers (
                upstream_oauth_provider_id,
                issuer,
                scope,
                token_endpoint_auth_method,
                token_endpoint_signing_alg,
                client_id,
                encrypted_client_secret,
                created_at,
                claims_imports
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
            Uuid::from(id),
            &issuer,
            scope.to_string(),
            token_endpoint_auth_method.to_string(),
            token_endpoint_signing_alg.as_ref().map(ToString::to_string),
            &client_id,
            encrypted_client_secret.as_deref(),
            created_at,
            Json(&claims_imports) as _,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer,
            scope,
            client_id,
            encrypted_client_secret,
            token_endpoint_signing_alg,
            token_endpoint_auth_method,
            created_at,
            claims_imports,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.add",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_provider.id = %id,
            upstream_oauth_provider.issuer = %issuer,
            upstream_oauth_provider.client_id = %client_id,
        ),
        err,
    )]
    #[allow(clippy::too_many_arguments)]
    async fn upsert(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        issuer: String,
        scope: Scope,
        token_endpoint_auth_method: OAuthClientAuthenticationMethod,
        token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
        client_id: String,
        encrypted_client_secret: Option<String>,
        claims_imports: UpstreamOAuthProviderClaimsImports,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();

        let created_at = sqlx::query_scalar!(
            r#"
                INSERT INTO upstream_oauth_providers (
                    upstream_oauth_provider_id,
                    issuer,
                    scope,
                    token_endpoint_auth_method,
                    token_endpoint_signing_alg,
                    client_id,
                    encrypted_client_secret,
                    created_at,
                    claims_imports
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (upstream_oauth_provider_id) 
                    DO UPDATE
                    SET
                        issuer = EXCLUDED.issuer,
                        scope = EXCLUDED.scope,
                        token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
                        token_endpoint_signing_alg = EXCLUDED.token_endpoint_signing_alg,
                        client_id = EXCLUDED.client_id,
                        encrypted_client_secret = EXCLUDED.encrypted_client_secret,
                        claims_imports = EXCLUDED.claims_imports
                RETURNING created_at
            "#,
            Uuid::from(id),
            &issuer,
            scope.to_string(),
            token_endpoint_auth_method.to_string(),
            token_endpoint_signing_alg.as_ref().map(ToString::to_string),
            &client_id,
            encrypted_client_secret.as_deref(),
            created_at,
            Json(&claims_imports) as _,
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer,
            scope,
            client_id,
            encrypted_client_secret,
            token_endpoint_signing_alg,
            token_endpoint_auth_method,
            created_at,
            claims_imports,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.delete_by_id",
        skip_all,
        fields(
            db.statement,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
                DELETE FROM upstream_oauth_providers
                WHERE upstream_oauth_provider_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.list_paginated",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn list_paginated(
        &mut self,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error> {
        let mut query = QueryBuilder::new(
            r#"
                SELECT
                    upstream_oauth_provider_id,
                    issuer,
                    scope,
                    client_id,
                    encrypted_client_secret,
                    token_endpoint_signing_alg,
                    token_endpoint_auth_method,
                    created_at,
                    claims_imports
                FROM upstream_oauth_providers
                WHERE 1 = 1
            "#,
        );

        query.generate_pagination("upstream_oauth_provider_id", pagination);

        let edges: Vec<ProviderLookup> = query
            .build_query_as()
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryInto::try_into)?;
        Ok(page)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.all",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn all(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error> {
        let res = sqlx::query_as!(
            ProviderLookup,
            r#"
                SELECT
                    upstream_oauth_provider_id,
                    issuer,
                    scope,
                    client_id,
                    encrypted_client_secret,
                    token_endpoint_signing_alg,
                    token_endpoint_auth_method,
                    created_at,
                    claims_imports as "claims_imports: Json<UpstreamOAuthProviderClaimsImports>"
                FROM upstream_oauth_providers
            "#,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        let res: Result<Vec<_>, _> = res.into_iter().map(TryInto::try_into).collect();
        Ok(res?)
    }
}
