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

use chrono::{DateTime, Duration, Utc};
use mas_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebSignatureAlg},
    oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
};
use mas_jose::JsonWebKeySet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DurationSeconds, TimestampSeconds};
use url::Url;

use crate::{
    oidc::{ApplicationType, SubjectType},
    requests::GrantType,
};

fn default_response_types() -> Vec<OAuthAuthorizationEndpointResponseType> {
    vec![OAuthAuthorizationEndpointResponseType::Code]
}

fn default_grant_types() -> Vec<GrantType> {
    vec![GrantType::AuthorizationCode]
}

const fn default_application_type() -> ApplicationType {
    ApplicationType::Web
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<Url>,

    #[serde(default = "default_response_types")]
    pub response_types: Vec<OAuthAuthorizationEndpointResponseType>,

    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<GrantType>,

    #[serde(default = "default_application_type")]
    pub application_type: ApplicationType,

    #[serde(default)]
    pub contacts: Vec<String>,

    #[serde(default)]
    pub client_name: Option<String>,

    #[serde(default)]
    pub logo_uri: Option<Url>,

    #[serde(default)]
    pub client_uri: Option<Url>,

    #[serde(default)]
    pub policy_uri: Option<Url>,

    #[serde(default)]
    pub tos_uri: Option<Url>,

    #[serde(default)]
    pub jwks_uri: Option<Url>,

    #[serde(default)]
    pub jwks: Option<JsonWebKeySet>,

    #[serde(default)]
    pub sector_identifier_uri: Option<Url>,

    #[serde(default)]
    pub subject_type: Option<SubjectType>,

    #[serde(default)]
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub request_object_signing_alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    pub request_object_encryption_alg: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub request_object_encryption_enc: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub default_max_age: Option<Duration>,

    #[serde(default)]
    pub require_auth_time: bool,

    #[serde(default)]
    pub default_acr_values: Vec<String>,

    #[serde(default)]
    pub initiate_login_uri: Option<Url>,

    #[serde(default)]
    pub request_uris: Option<Vec<Url>>,

    #[serde(default)]
    pub require_signed_request_object: bool,

    #[serde(default)]
    pub require_pushed_authorization_requests: bool,

    #[serde(default)]
    pub introspection_signed_response_alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    pub introspection_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    #[serde(default)]
    pub introspection_encrypted_response_enc: Option<JsonWebEncryptionAlg>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ClientRegistrationResponse {
    pub client_id: String,

    #[serde(default)]
    pub client_secret: Option<String>,

    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_id_issued_at: Option<DateTime<Utc>>,

    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_secret_expires_at: Option<DateTime<Utc>>,
}
