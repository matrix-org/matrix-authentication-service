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

    /// PKCE code challenge methods supported by this authorization server
    pub code_challenge_methods_supported: Option<HashSet<CodeChallengeMethod>>,

    /// URL of the authorization server's OAuth 2.0 introspection endpoint.
    pub introspection_endpoint: Option<Url>,

    pub userinfo_endpoint: Option<Url>,
}
