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

use chrono::{DateTime, Utc};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use oauth2_types::scope::Scope;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthProvider {
    pub id: Ulid,
    pub issuer: String,
    pub scope: Scope,
    pub client_id: String,
    pub encrypted_client_secret: Option<String>,
    pub token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
    pub token_endpoint_auth_method: OAuthClientAuthenticationMethod,
    pub created_at: DateTime<Utc>,
    pub claims_imports: ClaimsImports,
}

/// Whether to set the email as verified when importing it from the upstream
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SetEmailVerification {
    /// Set the email as verified
    Always,

    /// Never set the email as verified
    Never,

    /// Set the email as verified if the upstream provider claims it is verified
    #[default]
    Import,
}

impl SetEmailVerification {
    #[must_use]
    pub fn should_mark_as_verified(&self, upstream_verified: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Import => upstream_verified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClaimsImports {
    #[serde(default)]
    pub subject: SubjectPreference,

    #[serde(default)]
    pub localpart: ImportPreference,

    #[serde(default)]
    pub displayname: ImportPreference,

    #[serde(default)]
    pub email: ImportPreference,

    #[serde(default)]
    pub verify_email: SetEmailVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubjectPreference {
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportPreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,
}

impl std::ops::Deref for ImportPreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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

impl ImportAction {
    #[must_use]
    pub fn is_forced(&self) -> bool {
        matches!(self, Self::Force | Self::Require)
    }

    #[must_use]
    pub fn ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Require)
    }
}
