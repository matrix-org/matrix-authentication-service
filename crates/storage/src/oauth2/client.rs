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

use crate::{repository_impl, Clock};

/// An [`OAuth2ClientRepository`] helps interacting with [`Client`] saved in the
/// storage backend
#[async_trait]
pub trait OAuth2ClientRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an OAuth2 client by its ID
    ///
    /// Returns `None` if the client does not exist
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the client to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error>;

    /// Find an OAuth2 client by its client ID
    async fn find_by_client_id(&mut self, client_id: &str) -> Result<Option<Client>, Self::Error> {
        let Ok(id) = client_id.parse() else { return Ok(None) };
        self.lookup(id).await
    }

    /// Load a batch of OAuth2 clients by their IDs
    ///
    /// Returns a map of client IDs to clients. If a client does not exist, it
    /// is not present in the map.
    ///
    /// # Parameters
    ///
    /// * `ids`: The IDs of the clients to load
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error>;

    /// Add a new OAuth2 client
    ///
    /// Returns the client that was added
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `redirect_uris`: The list of redirect URIs used by this client
    /// * `encrypted_client_secret`: The encrypted client secret, if any
    /// * `grant_types`: The list of grant types this client can use
    /// * `contacts`: The list of contacts for this client
    /// * `client_name`: The human-readable name of this client, if given
    /// * `logo_uri`: The URI of the logo of this client, if given
    /// * `client_uri`: The URI of a website of this client, if given
    /// * `policy_uri`: The URI of the privacy policy of this client, if given
    /// * `tos_uri`: The URI of the terms of service of this client, if given
    /// * `jwks_uri`: The URI of the JWKS of this client, if given
    /// * `jwks`: The JWKS of this client, if given
    /// * `id_token_signed_response_alg`: The algorithm used to sign the ID
    ///   token
    /// * `userinfo_signed_response_alg`: The algorithm used to sign the user
    ///   info. If none, the user info endpoint will not sign the response
    /// * `token_endpoint_auth_method`: The authentication method used by this
    ///   client when calling the token endpoint
    /// * `token_endpoint_auth_signing_alg`: The algorithm used to sign the JWT
    ///   when using the `client_secret_jwt` or `private_key_jwt` authentication
    ///   methods
    /// * `initiate_login_uri`: The URI used to initiate a login, if given
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
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

    /// Add or replace a static client
    ///
    /// Returns the client that was added or replaced
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client_id`: The client ID
    /// * `client_auth_method`: The authentication method this client uses
    /// * `encrypted_client_secret`: The encrypted client secret, if any
    /// * `jwks`: The client JWKS, if any
    /// * `jwks_uri`: The client JWKS URI, if any
    /// * `redirect_uris`: The list of redirect URIs used by this client
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[allow(clippy::too_many_arguments)]
    async fn upsert_static(
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

    /// List all static clients
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error>;

    /// Get the list of scopes that the user has given consent for the given
    /// client
    ///
    /// # Parameters
    ///
    /// * `client`: The client to get the consent for
    /// * `user`: The user to get the consent for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn get_consent_for_user(
        &mut self,
        client: &Client,
        user: &User,
    ) -> Result<Scope, Self::Error>;

    /// Give consent for a set of scopes for the given client and user
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The client to give the consent for
    /// * `user`: The user to give the consent for
    /// * `scope`: The scope to give consent for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn give_consent_for_user(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: &User,
        scope: &Scope,
    ) -> Result<(), Self::Error>;

    /// Delete a client
    ///
    /// # Parameters
    ///
    /// * `client`: The client to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// client does not exist
    async fn delete(&mut self, client: Client) -> Result<(), Self::Error> {
        self.delete_by_id(client.id).await
    }

    /// Delete a client by ID
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the client to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// client does not exist
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;
}

repository_impl!(OAuth2ClientRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error>;

    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error>;

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

    async fn upsert_static(
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

    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error>;

    async fn delete(&mut self, client: Client) -> Result<(), Self::Error>;

    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;

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
);
