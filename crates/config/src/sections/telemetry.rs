// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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
use serde_with::skip_serializing_none;
use url::Url;

use super::ConfigurationSection;

/// Propagation format for incoming and outgoing requests
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Propagator {
    /// Propagate according to the W3C Trace Context specification
    TraceContext,

    /// Propagate according to the W3C Baggage specification
    Baggage,

    /// Propagate trace context with Jaeger compatible headers
    Jaeger,
}

fn otlp_endpoint_example() -> &'static str {
    "https://localhost:4318"
}

/// Exporter to use when exporting traces
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "exporter", rename_all = "lowercase", deny_unknown_fields)]
pub enum TracingExporterConfig {
    /// Don't export traces
    None,

    /// Export traces to the standard output. Only useful for debugging
    Stdout,

    /// Export traces to an OpenTelemetry protocol compatible endpoint
    Otlp {
        /// OTLP compatible endpoint
        #[schemars(url, example = "otlp_endpoint_example")]
        #[serde(default)]
        endpoint: Option<Url>,
    },
}

impl Default for TracingExporterConfig {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration related to exporting traces
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TracingConfig {
    /// Exporter to use when exporting traces
    #[serde(default, flatten)]
    pub exporter: TracingExporterConfig,

    /// List of propagation formats to use for incoming and outgoing requests
    pub propagators: Vec<Propagator>,
}

/// Exporter to use when exporting metrics
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "exporter", rename_all = "lowercase")]
pub enum MetricsExporterConfig {
    /// Don't export metrics
    None,

    /// Export metrics to stdout. Only useful for debugging
    Stdout,

    /// Export metrics to an OpenTelemetry protocol compatible endpoint
    Otlp {
        /// OTLP compatible endpoint
        #[schemars(url, example = "otlp_endpoint_example")]
        #[serde(default)]
        endpoint: Option<Url>,
    },

    /// Export metrics via Prometheus. An HTTP listener with the `prometheus`
    /// resource must be setup to expose the Promethes metrics.
    Prometheus,
}

impl Default for MetricsExporterConfig {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration related to exporting metrics
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct MetricsConfig {
    /// Exporter to use when exporting metrics
    #[serde(default, flatten)]
    pub exporter: MetricsExporterConfig,
}

fn sentry_dsn_example() -> &'static str {
    "https://public@host:port/1"
}

/// Configuration related to the Sentry integration
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct SentryConfig {
    /// Sentry DSN
    #[schemars(url, example = "sentry_dsn_example")]
    #[serde(default)]
    pub dsn: Option<String>,
}

/// Configuration related to sending monitoring data
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryConfig {
    /// Configuration related to exporting traces
    #[serde(default)]
    pub tracing: TracingConfig,

    /// Configuration related to exporting metrics
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Configuration related to the Sentry integration
    #[serde(default)]
    pub sentry: SentryConfig,
}

#[async_trait]
impl ConfigurationSection for TelemetryConfig {
    const PATH: Option<&'static str> = Some("telemetry");

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
