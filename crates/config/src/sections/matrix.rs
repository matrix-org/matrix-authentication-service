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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

fn default_homeserver() -> String {
    "localhost:8008".to_owned()
}

/// Configuration related to the Matrix homeserver
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatrixConfig {
    /// Time-to-live of a CSRF token in seconds
    #[serde(default = "default_homeserver")]
    pub homeserver: String,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            homeserver: default_homeserver(),
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for MatrixConfig {
    fn path() -> &'static str {
        "matrix"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use figment::Jail;

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    matrix:
                      homeserver: matrix.org
                "#,
            )?;

            let config = MatrixConfig::load_from_file("config.yaml")?;

            assert_eq!(config.homeserver, "matrix.org".to_owned());

            Ok(())
        });
    }
}
