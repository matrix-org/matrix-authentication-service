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

use mas_data_model::{AuthorizationGrant, Client, User};
use oauth2_types::registration::VerifiedClientMetadata;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct EvaluationResult {
    #[serde(rename = "result")]
    pub violations: Vec<Violation>,
}

impl EvaluationResult {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations.is_empty()
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "registration_method", rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub enum RegisterInput<'a> {
    Password {
        username: &'a str,
        password: &'a str,
        email: &'a str,
    },
}

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
pub struct AuthorizationGrantInput<'a> {
    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "std::collections::HashMap<String, serde_json::Value>")
    )]
    pub user: &'a User,

    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "std::collections::HashMap<String, serde_json::Value>")
    )]
    pub client: &'a Client,

    #[cfg_attr(
        feature = "jsonschema",
        schemars(with = "std::collections::HashMap<String, serde_json::Value>")
    )]
    pub authorization_grant: &'a AuthorizationGrant,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct EmailInput<'a> {
    pub email: &'a str,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "jsonschema", derive(schemars::JsonSchema))]
pub struct PasswordInput<'a> {
    pub password: &'a str,
}
