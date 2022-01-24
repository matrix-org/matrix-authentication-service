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
use lettre::{message::Mailbox, Address};
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

fn mailbox_schema(gen: &mut SchemaGenerator) -> Schema {
    // TODO: proper email schema
    String::json_schema(gen)
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmailSmtpMode {
    Plain,
    StartTls,
    Tls,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum EmailTransportConfig {
    Blackhole,
    Smtp {
        mode: EmailSmtpMode,
        hostname: String,

        #[serde(default)]
        port: Option<u16>,

        #[serde(flatten, default)]
        credentials: Option<Credentials>,
    },
    AwsSes,
}

impl Default for EmailTransportConfig {
    fn default() -> Self {
        Self::Blackhole
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    #[schemars(schema_with = "mailbox_schema")]
    pub from: Mailbox,

    #[schemars(schema_with = "mailbox_schema")]
    pub reply_to: Mailbox,

    #[serde(flatten)]
    pub transport: EmailTransportConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        let address = Address::new("root", "localhost").unwrap();
        let mailbox = Mailbox::new(Some("Authentication Service".to_string()), address);
        Self {
            from: mailbox.clone(),
            reply_to: mailbox,
            transport: EmailTransportConfig::Blackhole,
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for EmailConfig {
    fn path() -> &'static str {
        "email"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
