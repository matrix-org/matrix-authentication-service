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

mod branding;
mod clients;
mod database;
mod email;
mod experimental;
mod http;
mod matrix;
mod passwords;
mod policy;
mod secrets;
mod telemetry;
mod templates;
mod upstream_oauth2;

pub use self::{
    branding::BrandingConfig,
    clients::{ClientAuthMethodConfig, ClientConfig, ClientsConfig},
    database::DatabaseConfig,
    email::{EmailConfig, EmailSmtpMode, EmailTransportKind},
    experimental::ExperimentalConfig,
    http::{
        BindConfig as HttpBindConfig, HttpConfig, ListenerConfig as HttpListenerConfig,
        Resource as HttpResource, TlsConfig as HttpTlsConfig, UnixOrTcp,
    },
    matrix::MatrixConfig,
    passwords::{Algorithm as PasswordAlgorithm, PasswordsConfig},
    policy::PolicyConfig,
    secrets::SecretsConfig,
    telemetry::{
        MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
        TracingExporterKind,
    },
    templates::TemplatesConfig,
    upstream_oauth2::{
        ClaimsImports as UpstreamOAuth2ClaimsImports, DiscoveryMode as UpstreamOAuth2DiscoveryMode,
        EmailImportPreference as UpstreamOAuth2EmailImportPreference,
        ImportAction as UpstreamOAuth2ImportAction, PkceMethod as UpstreamOAuth2PkceMethod,
        SetEmailVerification as UpstreamOAuth2SetEmailVerification, UpstreamOAuth2Config,
    },
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

    /// Configuration related to sending emails
    #[serde(default)]
    pub email: EmailConfig,

    /// Application secrets
    pub secrets: SecretsConfig,

    /// Configuration related to user passwords
    #[serde(default)]
    pub passwords: PasswordsConfig,

    /// Configuration related to the homeserver
    pub matrix: MatrixConfig,

    /// Configuration related to the OPA policies
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Configuration related to upstream OAuth providers
    #[serde(default)]
    pub upstream_oauth2: UpstreamOAuth2Config,

    /// Configuration section for tweaking the branding of the service
    #[serde(default)]
    pub branding: BrandingConfig,

    /// Experimental configuration options
    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

#[async_trait]
impl ConfigurationSection for RootConfig {
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
            email: EmailConfig::generate(&mut rng).await?,
            passwords: PasswordsConfig::generate(&mut rng).await?,
            secrets: SecretsConfig::generate(&mut rng).await?,
            matrix: MatrixConfig::generate(&mut rng).await?,
            policy: PolicyConfig::generate(&mut rng).await?,
            upstream_oauth2: UpstreamOAuth2Config::generate(&mut rng).await?,
            branding: BrandingConfig::generate(&mut rng).await?,
            experimental: ExperimentalConfig::generate(&mut rng).await?,
        })
    }

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::error::Error> {
        self.clients.validate(figment)?;
        self.http.validate(figment)?;
        self.database.validate(figment)?;
        self.telemetry.validate(figment)?;
        self.templates.validate(figment)?;
        self.email.validate(figment)?;
        self.passwords.validate(figment)?;
        self.secrets.validate(figment)?;
        self.matrix.validate(figment)?;
        self.policy.validate(figment)?;
        self.upstream_oauth2.validate(figment)?;
        self.branding.validate(figment)?;
        self.experimental.validate(figment)?;

        Ok(())
    }

    fn test() -> Self {
        Self {
            clients: ClientsConfig::test(),
            http: HttpConfig::test(),
            database: DatabaseConfig::test(),
            telemetry: TelemetryConfig::test(),
            templates: TemplatesConfig::test(),
            passwords: PasswordsConfig::test(),
            email: EmailConfig::test(),
            secrets: SecretsConfig::test(),
            matrix: MatrixConfig::test(),
            policy: PolicyConfig::test(),
            upstream_oauth2: UpstreamOAuth2Config::test(),
            branding: BrandingConfig::test(),
            experimental: ExperimentalConfig::test(),
        }
    }
}

/// Partial configuration actually used by the server
#[allow(missing_docs)]
#[derive(Debug, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub templates: TemplatesConfig,

    #[serde(default)]
    pub email: EmailConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub passwords: PasswordsConfig,

    pub matrix: MatrixConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub branding: BrandingConfig,

    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

#[async_trait]
impl ConfigurationSection for AppConfig {
    async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self {
            http: HttpConfig::generate(&mut rng).await?,
            database: DatabaseConfig::generate(&mut rng).await?,
            templates: TemplatesConfig::generate(&mut rng).await?,
            email: EmailConfig::generate(&mut rng).await?,
            passwords: PasswordsConfig::generate(&mut rng).await?,
            secrets: SecretsConfig::generate(&mut rng).await?,
            matrix: MatrixConfig::generate(&mut rng).await?,
            policy: PolicyConfig::generate(&mut rng).await?,
            branding: BrandingConfig::generate(&mut rng).await?,
            experimental: ExperimentalConfig::generate(&mut rng).await?,
        })
    }

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::error::Error> {
        self.http.validate(figment)?;
        self.database.validate(figment)?;
        self.templates.validate(figment)?;
        self.email.validate(figment)?;
        self.passwords.validate(figment)?;
        self.secrets.validate(figment)?;
        self.matrix.validate(figment)?;
        self.policy.validate(figment)?;
        self.branding.validate(figment)?;
        self.experimental.validate(figment)?;

        Ok(())
    }

    fn test() -> Self {
        Self {
            http: HttpConfig::test(),
            database: DatabaseConfig::test(),
            templates: TemplatesConfig::test(),
            passwords: PasswordsConfig::test(),
            email: EmailConfig::test(),
            secrets: SecretsConfig::test(),
            matrix: MatrixConfig::test(),
            policy: PolicyConfig::test(),
            branding: BrandingConfig::test(),
            experimental: ExperimentalConfig::test(),
        }
    }
}

/// Partial config used by the `mas-cli config sync` command
#[allow(missing_docs)]
#[derive(Debug, Deserialize, Serialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub database: DatabaseConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub clients: ClientsConfig,

    #[serde(default)]
    pub upstream_oauth2: UpstreamOAuth2Config,
}

#[async_trait]
impl ConfigurationSection for SyncConfig {
    async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self {
            database: DatabaseConfig::generate(&mut rng).await?,
            secrets: SecretsConfig::generate(&mut rng).await?,
            clients: ClientsConfig::generate(&mut rng).await?,
            upstream_oauth2: UpstreamOAuth2Config::generate(&mut rng).await?,
        })
    }

    fn test() -> Self {
        Self {
            database: DatabaseConfig::test(),
            secrets: SecretsConfig::test(),
            clients: ClientsConfig::test(),
            upstream_oauth2: UpstreamOAuth2Config::test(),
        }
    }
}
