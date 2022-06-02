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

use std::path::PathBuf;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

fn default_wasm_module() -> PathBuf {
    "./policies/policy.wasm".into()
}

fn default_client_registration_endpoint() -> String {
    "client_registration/allow".to_string()
}

fn default_login_endpoint() -> String {
    "login/allow".to_string()
}

fn default_register_endpoint() -> String {
    "register/allow".to_string()
}

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    /// Path to the WASM module
    #[serde(default = "default_wasm_module")]
    pub wasm_module: PathBuf,

    /// Entrypoint to use when evaluating client registrations
    #[serde(default = "default_client_registration_endpoint")]
    pub client_registration_entrypoint: String,

    /// Entrypoint to use when evaluating user logins
    #[serde(default = "default_login_endpoint")]
    pub login_entrypoint: String,

    /// Entrypoint to use when evaluating user registrations
    #[serde(default = "default_register_endpoint")]
    pub register_entrypoint: String,

    /// Arbitrary data to pass to the policy
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            wasm_module: default_wasm_module(),
            client_registration_entrypoint: default_client_registration_endpoint(),
            login_entrypoint: default_login_endpoint(),
            register_entrypoint: default_register_endpoint(),
            data: None,
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for PolicyConfig {
    fn path() -> &'static str {
        "policy"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
