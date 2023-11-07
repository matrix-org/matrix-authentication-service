// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::ops::Deref;

use async_trait::async_trait;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ulid::Ulid;

use crate::ConfigurationSection;

/// Upstream OAuth 2.0 providers configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct UpstreamOAuth2Config {
    /// List of OAuth 2.0 providers
    pub providers: Vec<Provider>,
}

#[async_trait]
impl ConfigurationSection for UpstreamOAuth2Config {
    fn path() -> &'static str {
        "upstream_oauth2"
    }

    async fn generate<R>(_rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}

/// Authentication methods used against the OAuth 2.0 provider
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "token_endpoint_auth_method", rename_all = "snake_case")]
pub enum TokenAuthMethod {
    /// `none`: No authentication
    None,

    /// `client_secret_basic`: `client_id` and `client_secret` used as basic
    /// authorization credentials
    ClientSecretBasic { client_secret: String },

    /// `client_secret_post`: `client_id` and `client_secret` sent in the
    /// request body
    ClientSecretPost { client_secret: String },

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed using the `client_secret`
    ClientSecretJwt {
        client_secret: String,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
    },

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed by an asymmetric key
    PrivateKeyJwt {
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
    },
}

/// How to handle a claim
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// Ignore the claim
    #[default]
    Ignore,

    /// Suggest the claim value, but allow the user to change it
    Suggest,

    /// Force the claim value, but don't fail if it is missing
    Force,

    /// Force the claim value, and fail if it is missing
    Require,
}

/// What should be done with a attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct ImportPreference {
    /// How to handle the attribute
    #[serde(default)]
    pub action: ImportAction,
}

/// Should the email address be marked as verified
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SetEmailVerification {
    /// Mark the email address as verified
    Always,

    /// Don't mark the email address as verified
    Never,

    /// Mark the email address as verified if the upstream provider says it is
    /// through the `email_verified` claim
    #[default]
    Import,
}

/// What should be done for the subject attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct SubjectImportPreference {
    /// The Jinja2 template to use for the subject attribute
    ///
    /// If not provided, the default template is `{{ user.sub }}`
    #[serde(default)]
    pub template: Option<String>,
}

/// What should be done for the localpart attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct LocalpartImportPreference {
    /// How to handle the attribute
    #[serde(default)]
    pub action: ImportAction,

    /// The Jinja2 template to use for the localpart attribute
    ///
    /// If not provided, the default template is `{{ user.preferred_username }}`
    #[serde(default)]
    pub template: Option<String>,
}

/// What should be done for the displayname attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct DisplaynameImportPreference {
    /// How to handle the attribute
    #[serde(default)]
    pub action: ImportAction,

    /// The Jinja2 template to use for the displayname attribute
    ///
    /// If not provided, the default template is `{{ user.name }}`
    #[serde(default)]
    pub template: Option<String>,
}

/// What should be done with the email attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct EmailImportPreference {
    /// How to handle the claim
    #[serde(default)]
    pub action: ImportAction,

    /// The Jinja2 template to use for the email address attribute
    ///
    /// If not provided, the default template is `{{ user.email }}`
    #[serde(default)]
    pub template: Option<String>,

    /// Should the email address be marked as verified
    #[serde(default)]
    pub set_email_verification: SetEmailVerification,
}

/// How claims should be imported
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct ClaimsImports {
    /// How to determine the subject of the user
    #[serde(default)]
    pub subject: SubjectImportPreference,

    /// Import the localpart of the MXID
    #[serde(default)]
    pub localpart: LocalpartImportPreference,

    /// Import the displayname of the user.
    #[serde(default)]
    pub displayname: DisplaynameImportPreference,

    /// Import the email address of the user based on the `email` and
    /// `email_verified` claims
    #[serde(default)]
    pub email: EmailImportPreference,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Provider {
    /// An internal unique identifier for this provider
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub id: Ulid,

    /// The OIDC issuer URL
    pub issuer: String,

    /// The client ID to use when authenticating with the provider
    pub client_id: String,

    /// The scopes to request from the provider
    pub scope: String,

    #[serde(flatten)]
    pub token_auth_method: TokenAuthMethod,

    /// How claims should be imported from the `id_token` provided by the
    /// provider
    pub claims_imports: ClaimsImports,
}

impl Deref for Provider {
    type Target = TokenAuthMethod;

    fn deref(&self) -> &Self::Target {
        &self.token_auth_method
    }
}

impl TokenAuthMethod {
    #[doc(hidden)]
    #[must_use]
    pub fn client_auth_method(&self) -> OAuthClientAuthenticationMethod {
        match self {
            TokenAuthMethod::None => OAuthClientAuthenticationMethod::None,
            TokenAuthMethod::ClientSecretBasic { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretBasic
            }
            TokenAuthMethod::ClientSecretPost { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretPost
            }
            TokenAuthMethod::ClientSecretJwt { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretJwt
            }
            TokenAuthMethod::PrivateKeyJwt { .. } => OAuthClientAuthenticationMethod::PrivateKeyJwt,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn client_secret(&self) -> Option<&str> {
        match self {
            TokenAuthMethod::None | TokenAuthMethod::PrivateKeyJwt { .. } => None,
            TokenAuthMethod::ClientSecretBasic { client_secret }
            | TokenAuthMethod::ClientSecretPost { client_secret }
            | TokenAuthMethod::ClientSecretJwt { client_secret, .. } => Some(client_secret),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn client_auth_signing_alg(&self) -> Option<JsonWebSignatureAlg> {
        match self {
            TokenAuthMethod::ClientSecretJwt {
                token_endpoint_auth_signing_alg,
                ..
            }
            | TokenAuthMethod::PrivateKeyJwt {
                token_endpoint_auth_signing_alg,
                ..
            } => token_endpoint_auth_signing_alg.clone(),
            _ => None,
        }
    }
}
