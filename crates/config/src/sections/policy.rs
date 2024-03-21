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

use async_trait::async_trait;
use camino::Utf8PathBuf;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_policy_path() -> Utf8PathBuf {
    "./policies/policy.wasm".into()
}

#[cfg(feature = "docker")]
fn default_policy_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/policy.wasm".into()
}

#[cfg(feature = "dist")]
fn default_policy_path() -> Utf8PathBuf {
    "./share/policy.wasm".into()
}

fn default_client_registration_endpoint() -> String {
    "client_registration/violation".to_owned()
}

fn default_register_endpoint() -> String {
    "register/violation".to_owned()
}

fn default_authorization_grant_endpoint() -> String {
    "authorization_grant/violation".to_owned()
}

fn default_password_endpoint() -> String {
    "password/violation".to_owned()
}

fn default_email_endpoint() -> String {
    "email/violation".to_owned()
}

fn default_data() -> serde_json::Value {
    serde_json::json!({})
}

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    /// Path to the WASM module
    #[serde(default = "default_policy_path")]
    #[schemars(with = "String")]
    pub wasm_module: Utf8PathBuf,

    /// Entrypoint to use when evaluating client registrations
    #[serde(default = "default_client_registration_endpoint")]
    pub client_registration_entrypoint: String,

    /// Entrypoint to use when evaluating user registrations
    #[serde(default = "default_register_endpoint")]
    pub register_entrypoint: String,

    /// Entrypoint to use when evaluating authorization grants
    #[serde(default = "default_authorization_grant_endpoint")]
    pub authorization_grant_entrypoint: String,

    /// Entrypoint to use when changing password
    #[serde(default = "default_password_endpoint")]
    pub password_entrypoint: String,

    /// Entrypoint to use when adding an email address
    #[serde(default = "default_email_endpoint")]
    pub email_entrypoint: String,

    /// Arbitrary data to pass to the policy
    #[serde(default = "default_data")]
    pub data: serde_json::Value,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            wasm_module: default_policy_path(),
            client_registration_entrypoint: default_client_registration_endpoint(),
            register_entrypoint: default_register_endpoint(),
            authorization_grant_entrypoint: default_authorization_grant_endpoint(),
            password_entrypoint: default_password_endpoint(),
            email_entrypoint: default_email_endpoint(),
            data: default_data(),
        }
    }
}

#[async_trait]
impl ConfigurationSection for PolicyConfig {
    const PATH: Option<&'static str> = Some("policy");

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
