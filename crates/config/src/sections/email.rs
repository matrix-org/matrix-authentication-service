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

#![allow(deprecated)]

use std::num::NonZeroU16;

use async_trait::async_trait;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Credentials {
    /// Username for use to authenticate when connecting to the SMTP server
    pub username: String,

    /// Password for use to authenticate when connecting to the SMTP server
    pub password: String,
}

/// Encryption mode to use
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmailSmtpMode {
    /// Plain text
    Plain,

    /// StartTLS (starts as plain text then upgrade to TLS)
    StartTls,

    /// TLS
    Tls,
}

/// What backend should be used when sending emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum EmailTransportConfig {
    /// Don't send emails anywhere
    Blackhole,

    /// Send emails via an SMTP relay
    Smtp {
        /// Connection mode to the relay
        mode: EmailSmtpMode,

        /// Hostname to connect to
        #[schemars(with = "crate::schema::Hostname")]
        hostname: String,

        /// Port to connect to. Default is 25 for plain, 465 for TLS and 587 for
        /// StartTLS
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<NonZeroU16>,

        /// Set of credentials to use
        #[serde(flatten, default)]
        credentials: Option<Credentials>,
    },

    /// Send emails by calling sendmail
    Sendmail {
        /// Command to execute
        #[serde(default = "default_sendmail_command")]
        command: String,
    },

    /// Send emails via the AWS SESv2 API
    #[deprecated(note = "The AWS SESv2 backend has be removed.")]
    AwsSes,
}

impl Default for EmailTransportConfig {
    fn default() -> Self {
        Self::Blackhole
    }
}

fn default_email() -> String {
    r#""Authentication Service" <root@localhost>"#.to_owned()
}

fn default_sendmail_command() -> String {
    "sendmail".to_owned()
}

/// Configuration related to sending emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    /// Email address to use as From when sending emails
    #[serde(default = "default_email")]
    #[schemars(email)]
    pub from: String,

    /// Email address to use as Reply-To when sending emails
    #[serde(default = "default_email")]
    #[schemars(email)]
    pub reply_to: String,

    /// What backend should be used when sending emails
    #[serde(flatten, default)]
    pub transport: EmailTransportConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            from: default_email(),
            reply_to: default_email(),
            transport: EmailTransportConfig::Blackhole,
        }
    }
}

#[async_trait]
impl ConfigurationSection for EmailConfig {
    const PATH: Option<&'static str> = Some("email");

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
