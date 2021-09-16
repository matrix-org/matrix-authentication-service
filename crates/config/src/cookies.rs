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

use async_trait::async_trait;
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

fn secret_schema(gen: &mut SchemaGenerator) -> Schema {
    String::json_schema(gen)
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CookiesConfig {
    #[schemars(schema_with = "secret_schema")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub secret: [u8; 32],
}

#[async_trait]
impl ConfigurationSection<'_> for CookiesConfig {
    fn path() -> &'static str {
        "cookies"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self {
            secret: rand::random(),
        })
    }

    fn test() -> Self {
        Self { secret: [0xEA; 32] }
    }
}
