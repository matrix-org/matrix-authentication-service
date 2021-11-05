// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::collections::HashSet;

use serde::Serialize;
use serde_with::skip_serializing_none;
use url::Url;

use crate::{
    pkce::CodeChallengeMethod,
    requests::{ClientAuthenticationMethod, GrantType, ResponseMode},
};

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlgorithm {
    #[serde(rename = "none")]
    None,
    Hs256,
    Hs384,
    Hs512,
    Ps256,
    Ps384,
    Ps512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es256K,
    Es384,
    Es512,
    #[serde(rename = "EcDSA")]
    EcDsa,
}

// TODO: https://datatracker.ietf.org/doc/html/rfc8414#section-2
#[skip_serializing_none]
#[derive(Serialize, Clone)]
pub struct Metadata {
    /// The authorization server's issuer identifier, which is a URL that uses
    /// the "https" scheme and has no query or fragment components.
    pub issuer: Url,

    /// URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: Option<Url>,

    /// URL of the authorization server's token endpoint.
    pub token_endpoint: Option<Url>,

    /// URL of the authorization server's JWK Set document.
    pub jwks_uri: Option<Url>,

    /// URL of the authorization server's OAuth 2.0 Dynamic Client Registration
    /// endpoint.
    pub registration_endpoint: Option<Url>,

    /// JSON array containing a list of the OAuth 2.0 "scope" values that this
    /// authorization server supports.
    pub scopes_supported: Option<HashSet<String>>,

    /// JSON array containing a list of the OAuth 2.0 "response_type" values
    /// that this authorization server supports.
    pub response_types_supported: Option<HashSet<String>>,

    /// JSON array containing a list of the OAuth 2.0 "response_mode" values
    /// that this authorization server supports, as specified in "OAuth 2.0
    /// Multiple Response Type Encoding Practices".
    pub response_modes_supported: Option<HashSet<ResponseMode>>,

    /// JSON array containing a list of the OAuth 2.0 grant type values that
    /// this authorization server supports.
    pub grant_types_supported: Option<HashSet<GrantType>>,

    /// JSON array containing a list of client authentication methods supported
    /// by this token endpoint.
    pub token_endpoint_auth_methods_supported: Option<HashSet<ClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the Token Endpoint for the signature on the JWT used to authenticate
    /// the Client at the Token Endpoint for the private_key_jwt and
    /// client_secret_jwt authentication methods. Servers SHOULD support
    /// RS256. The value none MUST NOT be used.
    pub token_endpoint_auth_signing_alg_values_supported: Option<HashSet<SigningAlgorithm>>,

    /// PKCE code challenge methods supported by this authorization server
    pub code_challenge_methods_supported: Option<HashSet<CodeChallengeMethod>>,

    /// URL of the authorization server's OAuth 2.0 introspection endpoint.
    pub introspection_endpoint: Option<Url>,

    pub userinfo_endpoint: Option<Url>,
}
