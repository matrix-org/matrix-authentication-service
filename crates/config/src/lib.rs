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

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod cookies;
mod csrf;
mod database;
mod http;
mod oauth2;
mod telemetry;
mod templates;
mod util;

pub use self::{
    cookies::CookiesConfig,
    csrf::CsrfConfig,
    database::DatabaseConfig,
    http::HttpConfig,
    oauth2::{OAuth2ClientAuthMethodConfig, OAuth2ClientConfig, OAuth2Config},
    telemetry::{
        MetricsConfig, MetricsExporterConfig, Propagator, TelemetryConfig, TracingConfig,
        TracingExporterConfig,
    },
    templates::TemplatesConfig,
    util::ConfigurationSection,
};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RootConfig {
    pub oauth2: OAuth2Config,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    pub cookies: CookiesConfig,

    #[serde(default)]
    pub telemetry: TelemetryConfig,

    #[serde(default)]
    pub templates: TemplatesConfig,

    #[serde(default)]
    pub csrf: CsrfConfig,
}

#[async_trait]
impl ConfigurationSection<'_> for RootConfig {
    fn path() -> &'static str {
        ""
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self {
            oauth2: OAuth2Config::generate().await?,
            http: HttpConfig::generate().await?,
            database: DatabaseConfig::generate().await?,
            cookies: CookiesConfig::generate().await?,
            telemetry: TelemetryConfig::generate().await?,
            templates: TemplatesConfig::generate().await?,
            csrf: CsrfConfig::generate().await?,
        })
    }

    fn test() -> Self {
        Self {
            oauth2: OAuth2Config::test(),
            http: HttpConfig::test(),
            database: DatabaseConfig::test(),
            cookies: CookiesConfig::test(),
            telemetry: TelemetryConfig::test(),
            templates: TemplatesConfig::test(),
            csrf: CsrfConfig::test(),
        }
    }
}
