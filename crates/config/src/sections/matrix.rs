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
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

fn default_homeserver() -> String {
    "localhost:8008".to_owned()
}

fn default_endpoint() -> Url {
    Url::parse("http://localhost:8008/").unwrap()
}

/// Configuration related to the Matrix homeserver
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatrixConfig {
    /// The server name of the homeserver.
    #[serde(default = "default_homeserver")]
    pub homeserver: String,

    /// Shared secret to use for calls to the admin API
    pub secret: String,

    /// The base URL of the homeserver's client API
    #[serde(default = "default_endpoint")]
    pub endpoint: Url,
}

#[async_trait]
impl ConfigurationSection for MatrixConfig {
    fn path() -> &'static str {
        "matrix"
    }

    async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self {
            homeserver: default_homeserver(),
            secret: Alphanumeric.sample_string(&mut rng, 32),
            endpoint: default_endpoint(),
        })
    }

    fn test() -> Self {
        Self {
            homeserver: default_homeserver(),
            secret: "test".to_owned(),
            endpoint: default_endpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Yaml},
        Figment, Jail,
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    matrix:
                      homeserver: matrix.org
                      secret: test
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<MatrixConfig>("matrix")?;

            assert_eq!(&config.homeserver, "matrix.org");
            assert_eq!(&config.secret, "test");

            Ok(())
        });
    }
}
