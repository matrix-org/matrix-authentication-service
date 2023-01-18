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

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use mas_data_model::{Client, User};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use oauth2_types::{requests::GrantType, scope::Scope};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::Clock;

#[async_trait]
pub trait OAuth2ClientRepository: Send + Sync {
    type Error;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error>;

    async fn find_by_client_id(&mut self, client_id: &str) -> Result<Option<Client>, Self::Error> {
        let Ok(id) = client_id.parse() else { return Ok(None) };
        self.lookup(id).await
    }

    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error>;

    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        encrypted_client_secret: Option<String>,
        grant_types: Vec<GrantType>,
        contacts: Vec<String>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error>;

    #[allow(clippy::too_many_arguments)]
    async fn add_from_config(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client_id: Ulid,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error>;

    async fn get_consent_for_user(
        &mut self,
        client: &Client,
        user: &User,
    ) -> Result<Scope, Self::Error>;

    async fn give_consent_for_user(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: &User,
        scope: &Scope,
    ) -> Result<(), Self::Error>;
}
