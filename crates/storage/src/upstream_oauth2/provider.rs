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
use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, repository_impl, Clock, Pagination};

/// An [`UpstreamOAuthProviderRepository`] helps interacting with
/// [`UpstreamOAuthProvider`] saved in the storage backend
#[async_trait]
pub trait UpstreamOAuthProviderRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an upstream OAuth provider by its ID
    ///
    /// Returns `None` if the provider was not found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the provider to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error>;

    /// Add a new upstream OAuth provider
    ///
    /// Returns the newly created provider
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator
    /// * `clock`: The clock used to generate timestamps
    /// * `issuer`: The OIDC issuer of the provider
    /// * `scope`: The scope to request during the authorization flow
    /// * `token_endpoint_auth_method`: The token endpoint authentication method
    /// * `token_endpoint_auth_signing_alg`: The JWT signing algorithm to use
    ///   when then `client_secret_jwt` or `private_key_jwt` authentication
    ///   methods are used
    /// * `client_id`: The client ID to use when authenticating to the upstream
    /// * `encrypted_client_secret`: The encrypted client secret to use when
    ///   authenticating to the upstream
    /// * `claims_imports`: How claims should be imported from the upstream
    ///   provider
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
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
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Delete an upstream OAuth provider
    ///
    /// # Parameters
    ///
    /// * `provider`: The provider to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn delete(&mut self, provider: UpstreamOAuthProvider) -> Result<(), Self::Error> {
        self.delete_by_id(provider.id).await
    }

    /// Delete an upstream OAuth provider by its ID
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the provider to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;

    /// Insert or update an upstream OAuth provider
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `id`: The ID of the provider to update
    /// * `issuer`: The OIDC issuer of the provider
    /// * `scope`: The scope to request during the authorization flow
    /// * `token_endpoint_auth_method`: The token endpoint authentication method
    /// * `token_endpoint_auth_signing_alg`: The JWT signing algorithm to use
    ///   when then `client_secret_jwt` or `private_key_jwt` authentication
    ///   methods are used
    /// * `client_id`: The client ID to use when authenticating to the upstream
    /// * `encrypted_client_secret`: The encrypted client secret to use when
    ///   authenticating to the upstream
    /// * `claims_imports`: How claims should be imported from the upstream
    ///   provider
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
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
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Get a paginated list of upstream OAuth providers
    ///
    /// # Parameters
    ///
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list_paginated(
        &mut self,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error>;

    /// Get all upstream OAuth providers
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error>;
}

repository_impl!(UpstreamOAuthProviderRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error>;

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
        claims_imports: UpstreamOAuthProviderClaimsImports
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

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
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    async fn delete(&mut self, provider: UpstreamOAuthProvider) -> Result<(), Self::Error>;

    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;

    async fn list_paginated(
        &mut self,
        pagination: Pagination
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error>;

    async fn all(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error>;
);
