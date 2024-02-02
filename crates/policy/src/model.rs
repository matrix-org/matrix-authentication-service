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

//! Input and output types for policy evaluation.
//!
//! This is useful to generate JSON schemas for each input type, which can then
//! be type-checked by Open Policy Agent.

use mas_data_model::{Client, User};
use oauth2_types::{registration::VerifiedClientMetadata, scope::Scope};
use serde::{Deserialize, Serialize};

/// A single violation of a policy.
#[derive(Deserialize, Debug)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

/// The result of a policy evaluation.
#[derive(Deserialize, Debug)]
pub struct EvaluationResult {
    #[serde(rename = "result")]
    pub violations: Vec<Violation>,
}

impl std::fmt::Display for EvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for violation in &self.violations {
            if first {
                first = false;
            } else {
                write!(f, ", ")?;
            }
            write!(f, "{}", violation.msg)?;
        }
        Ok(())
    }
}

impl EvaluationResult {
    /// Returns true if the policy evaluation was successful.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Input for the user registration policy.
#[derive(Serialize, Debug)]
#[serde(tag = "registration_method")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub enum RegisterInput<'a> {
    #[serde(rename = "password")]
    Password {
        username: &'a str,
        password: &'a str,
        email: &'a str,
    },

    #[serde(rename = "upstream-oauth2")]
    UpstreamOAuth2 {
        username: &'a str,

        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
    },
}

/// Input for the client registration policy.
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct ClientRegistrationInput<'a> {
    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "std::collections::HashMap<String, serde_json::Value>")
    )]
    pub client_metadata: &'a VerifiedClientMetadata,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
}

/// Input for the authorization grant policy.
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct AuthorizationGrantInput<'a> {
    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "Option<std::collections::HashMap<String, serde_json::Value>>")
    )]
    pub user: Option<&'a User>,

    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "std::collections::HashMap<String, serde_json::Value>")
    )]
    pub client: &'a Client,

    #[cfg_attr(feature = "jsonschema", schemars(with = "String"))]
    pub scope: &'a Scope,

    pub grant_type: GrantType,
}

/// Input for the email add policy.
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct EmailInput<'a> {
    pub email: &'a str,
}

/// Input for the password set policy.
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct PasswordInput<'a> {
    pub password: &'a str,
}
