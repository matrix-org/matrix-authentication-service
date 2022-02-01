// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

fn default_builtin() -> bool {
    true
}

/// Configuration related to templates
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TemplatesConfig {
    /// Path to the folder that holds the custom templates
    #[serde(default)]
    pub path: Option<String>,

    /// Load the templates embedded in the binary
    #[serde(default = "default_builtin")]
    pub builtin: bool,
}

impl Default for TemplatesConfig {
    fn default() -> Self {
        Self {
            path: None,
            builtin: default_builtin(),
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for TemplatesConfig {
    fn path() -> &'static str {
        "templates"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
