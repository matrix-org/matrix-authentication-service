// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use mas_iana::{
    jose::JsonWebSignatureAlg,
    oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
};
use mas_jose::JsonWebKeySet;
use oauth2_types::requests::GrantType;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::traits::{StorageBackend, StorageBackendMarker};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    /// Client's JSON Web Key Set document, passed by value.
    Jwks(JsonWebKeySet),

    /// URL for the Client's JSON Web Key Set document.
    JwksUri(Url),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Client<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::ClientData,

    /// Client identifier
    pub client_id: String,

    pub encrypted_client_secret: Option<String>,

    /// Array of Redirection URI values used by the Client
    pub redirect_uris: Vec<Url>,

    /// Array containing a list of the OAuth 2.0 response_type values that the
    /// Client is declaring that it will restrict itself to using
    pub response_types: Vec<OAuthAuthorizationEndpointResponseType>,

    /// Array containing a list of the OAuth 2.0 Grant Types that the Client is
    /// declaring that it will restrict itself to using.
    pub grant_types: Vec<GrantType>,

    /// Array of e-mail addresses of people responsible for this Client
    pub contacts: Vec<String>,

    /// Name of the Client to be presented to the End-User
    pub client_name: Option<String>, // TODO: translations

    /// URL that references a logo for the Client application
    pub logo_uri: Option<Url>, // TODO: translations

    /// URL of the home page of the Client
    pub client_uri: Option<Url>, // TODO: translations

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the how the profile data will be used
    pub policy_uri: Option<Url>, // TODO: translations

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the Relying Party's terms of service
    pub tos_uri: Option<Url>, // TODO: translations

    pub jwks: Option<JwksOrJwksUri>,

    /// JWS alg algorithm REQUIRED for signing the ID Token issued to this
    /// Client
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// JWS alg algorithm REQUIRED for signing UserInfo Responses.
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// Requested authentication method for the token endpoint
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    /// JWS alg algorithm that MUST be used for signing the JWT used to
    /// authenticate the Client at the Token Endpoint for the private_key_jwt
    /// and client_secret_jwt authentication methods
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// URI using the https scheme that a third party can use to initiate a
    /// login by the RP
    pub initiate_login_uri: Option<Url>,
}

impl<S: StorageBackendMarker> From<Client<S>> for Client<()> {
    fn from(c: Client<S>) -> Self {
        Client {
            data: (),
            client_id: c.client_id,
            encrypted_client_secret: c.encrypted_client_secret,
            redirect_uris: c.redirect_uris,
            response_types: c.response_types,
            grant_types: c.grant_types,
            contacts: c.contacts,
            client_name: c.client_name,
            logo_uri: c.logo_uri,
            client_uri: c.client_uri,
            policy_uri: c.policy_uri,
            tos_uri: c.tos_uri,
            jwks: c.jwks,
            id_token_signed_response_alg: c.id_token_signed_response_alg,
            userinfo_signed_response_alg: c.userinfo_signed_response_alg,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            token_endpoint_auth_signing_alg: c.token_endpoint_auth_signing_alg,
            initiate_login_uri: c.initiate_login_uri,
        }
    }
}

#[derive(Debug, Error)]
pub enum InvalidRedirectUriError {
    #[error("redirect_uri is not allowed for this client")]
    NotAllowed,

    #[error("multiple redirect_uris registered for this client")]
    MultipleRegistered,

    #[error("client has no redirect_uri registered")]
    NoneRegistered,
}

impl<S: StorageBackend> Client<S> {
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        redirect_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        match (&self.redirect_uris[..], redirect_uri) {
            ([], _) => Err(InvalidRedirectUriError::NoneRegistered),
            ([one], None) => Ok(one),
            (_, None) => Err(InvalidRedirectUriError::MultipleRegistered),
            (uris, Some(uri)) if uris.contains(uri) => Ok(uri),
            _ => Err(InvalidRedirectUriError::NotAllowed),
        }
    }
}
