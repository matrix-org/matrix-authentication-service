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
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod clients;
mod csrf;
mod database;
mod email;
mod http;
mod matrix;
mod passwords;
mod policy;
mod secrets;
mod telemetry;
mod templates;

pub use self::{
    clients::{ClientAuthMethodConfig, ClientConfig, ClientsConfig},
    csrf::CsrfConfig,
    database::{ConnectConfig as DatabaseConnectConfig, DatabaseConfig},
    email::{EmailConfig, EmailSmtpMode, EmailTransportConfig},
    http::{
        BindConfig as HttpBindConfig, HttpConfig, ListenerConfig as HttpListenerConfig,
        Resource as HttpResource, TlsConfig as HttpTlsConfig, UnixOrTcp,
    },
    matrix::MatrixConfig,
    passwords::{Algorithm as PasswordAlgorithm, PasswordsConfig},
    policy::PolicyConfig,
    secrets::SecretsConfig,
    telemetry::{
        JaegerExporterProtocolConfig, MetricsConfig, MetricsExporterConfig, Propagator,
        TelemetryConfig, TracingConfig, TracingExporterConfig,
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

    /// Configuration related to user passwords
    #[serde(default)]
    pub passwords: PasswordsConfig,

    /// Configuration related to the homeserver
    #[serde(default)]
    pub matrix: MatrixConfig,

    /// Configuration related to the OPA policies
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[async_trait]
impl ConfigurationSection<'_> for RootConfig {
    fn path() -> &'static str {
        ""
    }

    async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self {
            clients: ClientsConfig::generate(&mut rng).await?,
            http: HttpConfig::generate(&mut rng).await?,
            database: DatabaseConfig::generate(&mut rng).await?,
            telemetry: TelemetryConfig::generate(&mut rng).await?,
            templates: TemplatesConfig::generate(&mut rng).await?,
            csrf: CsrfConfig::generate(&mut rng).await?,
            email: EmailConfig::generate(&mut rng).await?,
            passwords: PasswordsConfig::generate(&mut rng).await?,
            secrets: SecretsConfig::generate(&mut rng).await?,
            matrix: MatrixConfig::generate(&mut rng).await?,
            policy: PolicyConfig::generate(&mut rng).await?,
        })
    }

    fn test() -> Self {
        Self {
            clients: ClientsConfig::test(),
            http: HttpConfig::test(),
            database: DatabaseConfig::test(),
            telemetry: TelemetryConfig::test(),
            templates: TemplatesConfig::test(),
            passwords: PasswordsConfig::test(),
            csrf: CsrfConfig::test(),
            email: EmailConfig::test(),
            secrets: SecretsConfig::test(),
            matrix: MatrixConfig::test(),
            policy: PolicyConfig::test(),
        }
    }
}
