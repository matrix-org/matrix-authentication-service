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

mod clients;
mod csrf;
mod database;
mod email;
mod http;
mod secrets;
mod telemetry;
mod templates;

pub use self::{
    clients::{ClientAuthMethodConfig, ClientConfig, ClientsConfig},
    csrf::CsrfConfig,
    database::DatabaseConfig,
    email::{EmailConfig, EmailSmtpMode, EmailTransportConfig},
    http::HttpConfig,
    secrets::{Encrypter, SecretsConfig},
    telemetry::{
        MetricsConfig, MetricsExporterConfig, Propagator, TelemetryConfig, TracingConfig,
        TracingExporterConfig,
    },
    templates::TemplatesConfig,
};
use crate::util::ConfigurationSection;

/// Application configuration root
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RootConfig {
    /// List of OAuth 2.0/OIDC clients config
    #[serde(default)]
    pub clients: ClientsConfig,

    /// Configuration of the HTTP server
    #[serde(default)]
    pub http: HttpConfig,

    /// Database connection configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Configuration related to sending monitoring data
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Configuration related to templates
    #[serde(default)]
    pub templates: TemplatesConfig,

    /// Configuration related to Cross-Site Request Forgery protections
    #[serde(default)]
    pub csrf: CsrfConfig,

    /// Configuration related to sending emails
    #[serde(default)]
    pub email: EmailConfig,

    /// Application secrets
    pub secrets: SecretsConfig,
}

#[async_trait]
impl ConfigurationSection<'_> for RootConfig {
    fn path() -> &'static str {
        ""
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self {
            clients: ClientsConfig::generate().await?,
            http: HttpConfig::generate().await?,
            database: DatabaseConfig::generate().await?,
            telemetry: TelemetryConfig::generate().await?,
            templates: TemplatesConfig::generate().await?,
            csrf: CsrfConfig::generate().await?,
            email: EmailConfig::generate().await?,
            secrets: SecretsConfig::generate().await?,
        })
    }

    fn test() -> Self {
        Self {
            clients: ClientsConfig::test(),
            http: HttpConfig::test(),
            database: DatabaseConfig::test(),
            telemetry: TelemetryConfig::test(),
            templates: TemplatesConfig::test(),
            csrf: CsrfConfig::test(),
            email: EmailConfig::test(),
            secrets: SecretsConfig::test(),
        }
    }
}
