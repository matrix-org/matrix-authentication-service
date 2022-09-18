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

use std::num::NonZeroU16;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use url::Url;

use super::ConfigurationSection;

/// Propagation format for incoming and outgoing requests
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Propagator {
    /// Propagate according to the W3C Trace Context specification
    TraceContext,

    /// Propagate according to the W3C Baggage specification
    Baggage,

    /// Propagate trace context with Jaeger compatible headers
    Jaeger,

    /// Propagate trace context with Zipkin compatible headers (single `b3`
    /// header variant)
    B3,

    /// Propagate trace context with Zipkin compatible headers (multiple
    /// `x-b3-*` headers variant)
    B3Multi,
}

fn otlp_endpoint_example() -> &'static str {
    "https://localhost:4317"
}

fn zipkin_collector_endpoint_example() -> &'static str {
    "http://127.0.0.1:9411/api/v2/spans"
}

/// The protocol to use by the Jaeger exporter
///
/// Defaults to `udp/thrift.compact`
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "protocol", try_from = "JaegerExporterKitchenSink")]
pub enum JaegerExporterProtocolConfig {
    /// Thrift over HTTP
    #[serde(rename = "http/thrift.binary")]
    HttpThriftBinary {
        /// Full URL of the Jaeger HTTP endpoint
        ///
        /// Defaults to `http://localhost:14268/api/traces`
        endpoint: String,

        /// Username to be used for HTTP basic authentication
        username: Option<String>,

        /// Password to be used for HTTP basic authentication
        password: Option<String>,
    },

    /// Thrift with compact encoding over UDP
    #[serde(rename = "udp/thrift.compact")]
    UdpThriftCompact {
        /// Hostname of the Jaeger agent
        ///
        /// Defaults to `localhost`
        agent_host: String,

        /// `udp/thrift.compact` port of the Jaeger agent
        ///
        /// Defaults to `6831`
        agent_port: u16,
    },
}

#[derive(Clone, Debug, Deserialize)]
enum JaegerProtocol {
    #[serde(rename = "http/thrift.binary")]
    HttpThriftBinary,

    #[serde(rename = "grpc")]
    Grpc,

    #[serde(rename = "udp/thrift.compact")]
    UdpThriftCompact,

    #[serde(rename = "udp/thrift.binary")]
    UdpThriftBinary,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JaegerExporterKitchenSink {
    protocol: Option<JaegerProtocol>,
    endpoint: Option<Url>,
    username: Option<String>,
    password: Option<String>,
    agent_host: Option<String>,
    agent_port: Option<NonZeroU16>,
}

#[derive(Error, Debug)]
#[error("Invalid Jaeger exporter config")]
enum InvalidJaegerConfig {
    UnsupportedProtocol,
    UnsupportedField,
}

impl TryFrom<JaegerExporterKitchenSink> for JaegerExporterProtocolConfig {
    type Error = InvalidJaegerConfig;

    fn try_from(value: JaegerExporterKitchenSink) -> Result<Self, Self::Error> {
        match value {
            JaegerExporterKitchenSink {
                protocol: Some(JaegerProtocol::UdpThriftCompact) | None,
                endpoint: None,
                username: None,
                password: None,
                agent_host: host,
                agent_port: port,
            } => Ok(Self::UdpThriftCompact {
                agent_host: host.unwrap_or_else(|| "localhost".into()),
                agent_port: port.map_or(6831, u16::from),
            }),

            JaegerExporterKitchenSink {
                protocol: Some(JaegerProtocol::HttpThriftBinary),
                endpoint,
                username,
                password,
                agent_host: None,
                agent_port: None,
            } => Ok(Self::HttpThriftBinary {
                endpoint: endpoint.map_or_else(
                    || "http://localhost:14268/api/traces".into(),
                    |u| u.to_string(),
                ),
                username,
                password,
            }),

            JaegerExporterKitchenSink {
                protocol:
                    Some(JaegerProtocol::HttpThriftBinary | JaegerProtocol::UdpThriftCompact) | None,
                ..
            } => Err(InvalidJaegerConfig::UnsupportedField),

            JaegerExporterKitchenSink {
                protocol: Some(JaegerProtocol::Grpc | JaegerProtocol::UdpThriftBinary),
                ..
            } => Err(InvalidJaegerConfig::UnsupportedProtocol),
        }
    }
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

    /// Export traces to a Jaeger agent
    Jaeger(JaegerExporterProtocolConfig),

    /// Export traces to a Zipkin collector
    Zipkin {
        /// Zipkin collector endpoint
        #[schemars(url, example = "zipkin_collector_endpoint_example")]
        #[serde(default)]
        collector_endpoint: Option<Url>,
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

    /// Export metrics by exposing a Prometheus-compatible endpoint
    Prometheus {
        /// IP and port on which the Prometheus endpoint should be exposed
        address: String,
    },
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

/// Configuration related to sending monitoring data
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryConfig {
    /// Configuration related to exporting traces
    #[serde(default)]
    pub tracing: TracingConfig,

    /// Configuration related to exporting metrics
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[async_trait]
impl ConfigurationSection<'_> for TelemetryConfig {
    fn path() -> &'static str {
        "telemetry"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
