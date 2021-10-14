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

use std::net::SocketAddr;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use super::ConfigurationSection;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Propagator {
    TraceContext,
    Baggage,
    Jaeger,
    B3,
    B3Multi,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "exporter", rename_all = "lowercase")]
pub enum TracingExporterConfig {
    None,
    Stdout,
    Otlp {
        #[serde(default)]
        endpoint: Option<Url>,
    },
    Jaeger {
        #[serde(default)]
        agent_endpoint: Option<SocketAddr>,
    },
    Zipkin {
        #[serde(default)]
        collector_endpoint: Option<Url>,
    },
}

impl Default for TracingExporterConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TracingConfig {
    #[serde(default, flatten)]
    pub exporter: TracingExporterConfig,

    pub propagators: Vec<Propagator>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "exporter", rename_all = "lowercase")]
pub enum MetricsExporterConfig {
    None,
    Stdout,
    Otlp {
        #[serde(default)]
        endpoint: Option<url::Url>,
    },
}

impl Default for MetricsExporterConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct MetricsConfig {
    #[serde(default, flatten)]
    pub exporter: MetricsExporterConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub tracing: TracingConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[async_trait]
impl ConfigurationSection<'_> for TelemetryConfig {
    fn path() -> &'static str {
        "telemetry"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Default::default())
    }

    fn test() -> Self {
        Default::default()
    }
}
