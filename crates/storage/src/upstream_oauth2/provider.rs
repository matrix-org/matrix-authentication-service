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
use mas_data_model::UpstreamOAuthProvider;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, Clock, Pagination};

#[async_trait]
pub trait UpstreamOAuthProviderRepository: Send + Sync {
    type Error;

    /// Lookup an upstream OAuth provider by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error>;

    /// Add a new upstream OAuth provider
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
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Get a paginated list of upstream OAuth providers
    async fn list_paginated(
        &mut self,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error>;

    /// Get all upstream OAuth providers
    async fn all(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error>;
}
