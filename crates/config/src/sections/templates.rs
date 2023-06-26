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
use camino::Utf8PathBuf;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

#[cfg(not(feature = "docker"))]
fn default_path() -> Utf8PathBuf {
    "./templates/".into()
}

#[cfg(feature = "docker")]
fn default_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/templates/".into()
}

/// Configuration related to templates
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TemplatesConfig {
    /// Path to the folder which holds the templates
    #[serde(default = "default_path")]
    #[schemars(with = "Option<String>")]
    pub path: Utf8PathBuf,
}

impl Default for TemplatesConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
        }
    }
}

#[async_trait]
impl ConfigurationSection for TemplatesConfig {
    fn path() -> &'static str {
        "templates"
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
