// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use chrono::Duration;
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tide::Middleware;

use super::ConfigurationSection;
use crate::middlewares::CsrfMiddleware;

fn default_ttl() -> Duration {
    Duration::hours(1)
}

fn default_cookie_name() -> String {
    "csrf".to_string()
}

fn key_schema(gen: &mut SchemaGenerator) -> Schema {
    String::json_schema(gen)
}

fn ttl_schema(gen: &mut SchemaGenerator) -> Schema {
    u64::json_schema(gen)
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CsrfConfig {
    #[schemars(schema_with = "key_schema")]
    #[serde_as(as = "serde_with::hex::Hex")]
    key: [u8; 32],

    #[serde(default = "default_cookie_name")]
    cookie_name: String,

    #[schemars(schema_with = "ttl_schema")]
    #[serde(default = "default_ttl")]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    ttl: Duration,
}

impl CsrfConfig {
    pub fn into_middleware<State: Clone + Send + Sync + 'static>(self) -> impl Middleware<State> {
        let ttl = self.ttl;
        let cookie_name = self.cookie_name.clone();
        let protection = self.key;
        CsrfMiddleware::new(protection, cookie_name, ttl)
    }
}

impl ConfigurationSection<'_> for CsrfConfig {
    fn path() -> &'static str {
        "csrf"
    }

    fn generate() -> Self {
        Self {
            key: rand::random(),
            ttl: default_ttl(),
            cookie_name: default_cookie_name(),
        }
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
                    csrf:
                      key: 0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF
                      ttl: 1800
                "#,
            )?;

            let config = CsrfConfig::load_from_file("config.yaml")?;

            assert_eq!(
                config.key,
                [
                    0x00, 0x00, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66,
                    0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC,
                    0xDD, 0xDD, 0xEE, 0xEE, 0xFF, 0xFF,
                ]
            );

            assert_eq!(config.ttl, Duration::minutes(30));

            Ok(())
        })
    }
}
