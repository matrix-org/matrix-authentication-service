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

use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

fn secret_schema(gen: &mut SchemaGenerator) -> Schema {
    String::json_schema(gen)
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionConfig {
    #[schemars(schema_with = "secret_schema")]
    #[serde_as(as = "serde_with::hex::Hex")]
    secret: Vec<u8>,
}

// impl SessionConfig {
//     pub fn to_middleware<State: Clone + Send + Sync + 'static>(
//         &self,
//         store: impl SessionStore,
//     ) -> impl Middleware<State> {
//         SessionMiddleware::new(store, &self.secret)
//     }
// }

impl ConfigurationSection<'_> for SessionConfig {
    fn path() -> &'static str {
        "session"
    }

    fn generate() -> Self {
        let secret: [u8; 32] = rand::random();

        Self {
            secret: secret.into(),
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
                    session:
                      secret: 00112233445566778899AABBCCDDEEFF
                "#,
            )?;

            let config = SessionConfig::load_from_file("config.yaml")?;

            assert_eq!(
                config.secret,
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                    0xDD, 0xEE, 0xFF,
                ]
            );

            Ok(())
        })
    }
}
