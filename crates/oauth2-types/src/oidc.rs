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

use mas_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::{
        OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
        PkceCodeChallengeMethod,
    },
};
use serde::Serialize;
use serde_with::skip_serializing_none;
use url::Url;

use crate::requests::{Display, GrantType, ResponseMode};

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Public,
    Pairwise,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ClaimType {
    Normal,
    Aggregated,
    Distributed,
}

/// Authorization server metadata, as described by the
/// [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata)
#[skip_serializing_none]
#[derive(Serialize, Clone, Default)]
pub struct Metadata {
    /// Authorization server's issuer identifier URL.
    pub issuer: Option<Url>,

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
    pub response_types_supported: Option<HashSet<OAuthAuthorizationEndpointResponseType>>,

    /// JSON array containing a list of the OAuth 2.0 "response_mode" values
    /// that this authorization server supports.
    pub response_modes_supported: Option<HashSet<ResponseMode>>,

    /// JSON array containing a list of the OAuth 2.0 grant type values that
    /// this authorization server supports.
    pub grant_types_supported: Option<HashSet<GrantType>>,

    /// JSON array containing a list of client authentication methods supported
    /// by this token endpoint.
    pub token_endpoint_auth_methods_supported: Option<HashSet<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the token endpoint for the signature on the JWT used to authenticate the
    /// client at the token endpoint.
    pub token_endpoint_auth_signing_alg_values_supported: Option<HashSet<JsonWebSignatureAlg>>,

    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the authorization server.
    pub service_documentation: Option<Url>,

    // TODO: type
    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of language tag values from BCP 47. If omitted, the set of
    /// supported languages and scripts is unspecified.
    pub ui_locales_supported: Option<HashSet<String>>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's requirements on how the
    /// client can use the data provided by the authorization server.
    pub op_policy_uri: Option<Url>,

    /// URL that the authorization server provides to the person registering the
    /// client to read about the authorization server's terms of service.
    pub op_tos_uri: Option<Url>,

    /// URL of the authorization server's OAuth 2.0 revocation endpoint.
    pub revocation_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods supported
    /// by this revocation endpoint.
    pub revocation_endpoint_auth_methods_supported:
        Option<HashSet<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the revocation endpoint for the signature on the JWT used to
    /// authenticate the client at the revocation endpoint.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<HashSet<JsonWebSignatureAlg>>,

    /// URL of the authorization server's OAuth 2.0 introspection endpoint.
    pub introspection_endpoint: Option<Url>,

    /// JSON array containing a list of client authentication methods supported
    /// by this introspection endpoint.
    pub introspection_endpoint_auth_methods_supported:
        Option<HashSet<OAuthClientAuthenticationMethod>>,

    /// JSON array containing a list of the JWS signing algorithms supported by
    /// the introspection endpoint for the signature on the JWT used to
    /// authenticate the client at the introspection endpoint.
    pub introspection_endpoint_auth_signing_alg_values_supported:
        Option<HashSet<JsonWebSignatureAlg>>,

    /// PKCE code challenge methods supported by this authorization server.
    pub code_challenge_methods_supported: Option<HashSet<PkceCodeChallengeMethod>>,

    /// URL of the OP's UserInfo Endpoint.
    pub userinfo_endpoint: Option<Url>,

    /// JSON array containing a list of the Authentication Context Class
    /// References that this OP supports.
    pub acr_values_supported: Option<HashSet<String>>,

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports.
    pub subject_types_supported: Option<HashSet<SubjectType>>,

    /// JSON array containing a list of the JWS "alg" values supported by the OP
    /// for the ID Token.
    pub id_token_signing_alg_values_supported: Option<HashSet<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE "alg" values supported by the OP
    /// for the ID Token.
    pub id_token_encryption_alg_values_supported: Option<HashSet<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE "enc" values supported by the OP
    /// for the ID Token.
    pub id_token_encryption_enc_values_supported: Option<HashSet<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS "alg" values supported by the
    /// UserInfo Endpoint.
    pub userinfo_signing_alg_values_supported: Option<HashSet<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE "alg" values supported by the
    /// UserInfo Endpoint.
    pub userinfo_encryption_alg_values_supported: Option<HashSet<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE "enc" values supported by the
    /// UserInfo Endpoint.
    pub userinfo_encryption_enc_values_supported: Option<HashSet<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the JWS "alg" values supported by the OP
    /// for Request Objects.
    pub request_object_signing_alg_values_supported: Option<HashSet<JsonWebSignatureAlg>>,

    /// JSON array containing a list of the JWE "alg" values supported by the OP
    /// for Request Objects.
    pub request_object_encryption_alg_values_supported: Option<HashSet<JsonWebEncryptionAlg>>,

    /// JSON array containing a list of the JWE "enc" values supported by the OP
    /// for Request Objects.
    pub request_object_encryption_enc_values_supported: Option<HashSet<JsonWebEncryptionEnc>>,

    /// JSON array containing a list of the "display" parameter values that the
    /// OpenID Provider supports.
    pub display_values_supported: Option<HashSet<Display>>,

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports.
    pub claim_types_supported: Option<HashSet<ClaimType>>,

    /// JSON array containing a list of the Claim Names of the Claims that the
    /// OpenID Provider MAY be able to supply values for.
    pub claims_supported: Option<HashSet<String>>,

    // TODO: type
    /// Languages and scripts supported for values in Claims being returned,
    /// represented as a JSON array of BCP 47 language tag values.
    pub claims_locales_supported: Option<HashSet<String>>,

    /// Boolean value specifying whether the OP supports use of the "claims"
    /// parameter.
    pub claims_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the "request"
    /// parameter.
    pub request_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the
    /// "request_uri" parameter.
    pub request_uri_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP requires any "request_uri"
    /// values used to be pre-registered.
    pub require_request_uri_registration: Option<bool>,

    /// Indicates where authorization request needs to be protected as Request
    /// Object and provided through either request or request_uri parameter.
    pub require_signed_request_object: Option<bool>,

    /// URL of the authorization server's pushed authorization request endpoint.
    pub pushed_authorization_request_endpoint: Option<bool>,

    /// Indicates whether the authorization server accepts authorization
    /// requests only via PAR.
    pub require_pushed_authorization_requests: Option<bool>,
}
