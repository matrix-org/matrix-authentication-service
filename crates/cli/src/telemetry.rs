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

use std::{net::SocketAddr, time::Duration};

use anyhow::bail;
use mas_config::{MetricsExporterConfig, Propagator, TelemetryConfig, TracingExporterConfig};
use opentelemetry::{
    global,
    propagation::TextMapPropagator,
    sdk::{
        self,
        propagation::{BaggagePropagator, TextMapCompositePropagator, TraceContextPropagator},
        trace::{Sampler, Tracer},
        Resource,
    },
};
#[cfg(feature = "jaeger")]
use opentelemetry_jaeger::Propagator as JaegerPropagator;
use opentelemetry_semantic_conventions as semcov;
#[cfg(feature = "zipkin")]
use opentelemetry_zipkin::{B3Encoding, Propagator as ZipkinPropagator};
use url::Url;

pub async fn setup(config: &TelemetryConfig) -> anyhow::Result<Option<Tracer>> {
    global::set_error_handler(|e| tracing::error!("{}", e))?;
    let propagator = propagator(&config.tracing.propagators)?;

    // The CORS filter needs to know what headers it should whitelist for
    // CORS-protected requests.
    mas_http::set_propagator(&propagator);
    global::set_text_map_propagator(propagator);

    let tracer = tracer(&config.tracing.exporter).await?;
    meter(&config.metrics.exporter)?;
    Ok(tracer)
}

pub fn shutdown() {
    global::shutdown_tracer_provider();
}

fn match_propagator(
    propagator: Propagator,
) -> anyhow::Result<Box<dyn TextMapPropagator + Send + Sync>> {
    match propagator {
        Propagator::TraceContext => Ok(Box::new(TraceContextPropagator::new())),
        Propagator::Baggage => Ok(Box::new(BaggagePropagator::new())),

        #[cfg(feature = "jaeger")]
        Propagator::Jaeger => Ok(Box::new(JaegerPropagator::new())),

        #[cfg(feature = "zipkin")]
        Propagator::B3 => Ok(Box::new(ZipkinPropagator::with_encoding(
            B3Encoding::SingleHeader,
        ))),

        #[cfg(feature = "zipkin")]
        Propagator::B3Multi => Ok(Box::new(ZipkinPropagator::with_encoding(
            B3Encoding::MultipleHeader,
        ))),

        p => bail!(
            "The service was compiled without support for the {:?} propagator, but config uses it.",
            p
        ),
    }
}

fn propagator(propagators: &[Propagator]) -> anyhow::Result<impl TextMapPropagator> {
    let propagators: Result<Vec<_>, _> =
        propagators.iter().cloned().map(match_propagator).collect();

    Ok(TextMapCompositePropagator::new(propagators?))
}

#[cfg(any(feature = "otlp", feature = "jaeger"))]
async fn http_client() -> anyhow::Result<impl opentelemetry_http::HttpClient + 'static> {
    let client = mas_http::make_untraced_client().await?;
    let client =
        opentelemetry_http::hyper::HyperClient::new_with_timeout(client, Duration::from_secs(30));
    Ok(client)
}

fn stdout_tracer() -> Tracer {
    sdk::export::trace::stdout::new_pipeline()
        .with_pretty_print(true)
        .with_trace_config(trace_config())
        .install_simple()
}

#[cfg(feature = "otlp")]
fn otlp_tracer(endpoint: &Option<Url>) -> anyhow::Result<Tracer> {
    use opentelemetry_otlp::WithExportConfig;

    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(trace_config())
        .install_batch(opentelemetry::runtime::Tokio)?;

    Ok(tracer)
}

#[cfg(not(feature = "otlp"))]
fn otlp_tracer(_endpoint: &Option<Url>) -> anyhow::Result<Tracer> {
    anyhow::bail!("The service was compiled without OTLP exporter support, but config exports traces via OTLP.")
}

#[cfg(not(feature = "jaeger"))]
fn jaeger_tracer(_agent_endpoint: &Option<SocketAddr>) -> anyhow::Result<Tracer> {
    anyhow::bail!("The service was compiled without Jaeger exporter support, but config exports traces via Jaeger.")
}

#[cfg(feature = "jaeger")]
fn jaeger_tracer(agent_endpoint: &Option<SocketAddr>) -> anyhow::Result<Tracer> {
    // TODO: also support exporting to a Jaeger collector & skip the agent
    let mut pipeline = opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_trace_config(trace_config());

    if let Some(agent_endpoint) = agent_endpoint {
        pipeline = pipeline.with_endpoint(agent_endpoint);
    }

    let tracer = pipeline.install_batch(opentelemetry::runtime::Tokio)?;

    Ok(tracer)
}

#[cfg(not(feature = "zipkin"))]
fn zipkin_tracer(_collector_endpoint: &Option<Url>) -> anyhow::Result<Tracer> {
    anyhow::bail!("The service was compiled without Jaeger exporter support, but config exports traces via Jaeger.")
}

#[cfg(feature = "zipkin")]
async fn zipkin_tracer(collector_endpoint: &Option<Url>) -> anyhow::Result<Tracer> {
    let http_client = http_client().await?;

    let mut pipeline = opentelemetry_zipkin::new_pipeline()
        .with_http_client(http_client)
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_trace_config(trace_config());

    if let Some(collector_endpoint) = collector_endpoint {
        pipeline = pipeline.with_collector_endpoint(collector_endpoint.to_string());
    }

    let tracer = pipeline.install_batch(opentelemetry::runtime::Tokio)?;

    Ok(tracer)
}

async fn tracer(config: &TracingExporterConfig) -> anyhow::Result<Option<Tracer>> {
    let tracer = match config {
        TracingExporterConfig::None => return Ok(None),
        TracingExporterConfig::Stdout => stdout_tracer(),
        TracingExporterConfig::Otlp { endpoint } => otlp_tracer(endpoint)?,
        TracingExporterConfig::Jaeger { agent_endpoint } => jaeger_tracer(agent_endpoint)?,
        TracingExporterConfig::Zipkin { collector_endpoint } => {
            zipkin_tracer(collector_endpoint).await?
        }
    };

    Ok(Some(tracer))
}

#[cfg(feature = "otlp")]
fn otlp_meter(endpoint: &Option<url::Url>) -> anyhow::Result<()> {
    use opentelemetry_otlp::WithExportConfig;

    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }

    opentelemetry_otlp::new_pipeline()
        .metrics(
            sdk::metrics::selectors::simple::histogram([0.1, 0.2, 0.5, 1.0, 5.0, 10.0]),
            sdk::export::metrics::aggregation::stateless_temporality_selector(),
            opentelemetry::runtime::Tokio,
        )
        .with_exporter(exporter)
        .build()?;

    Ok(())
}

#[cfg(not(feature = "otlp"))]
fn otlp_meter(_endpoint: &Option<url::Url>) -> anyhow::Result<()> {
    anyhow::bail!("The service was compiled without OTLP exporter support, but config exports metrics via OTLP.")
}

fn stdout_meter() -> anyhow::Result<()> {
    let exporter = sdk::export::metrics::stdout().build()?;
    let controller = sdk::metrics::controllers::basic(
        sdk::metrics::processors::factory(
            sdk::metrics::selectors::simple::histogram([0.1, 0.2, 0.5, 1.0, 5.0, 10.0]),
            exporter.temporality_selector(),
        )
        .with_memory(true),
    )
    .with_exporter(exporter)
    .build();
    global::set_meter_provider(controller);
    Ok(())
}

fn meter(config: &MetricsExporterConfig) -> anyhow::Result<()> {
    match config {
        MetricsExporterConfig::None => {}
        MetricsExporterConfig::Stdout => stdout_meter()?,
        MetricsExporterConfig::Otlp { endpoint } => otlp_meter(endpoint)?,
    };

    Ok(())
}

fn trace_config() -> sdk::trace::Config {
    sdk::trace::config()
        .with_resource(resource())
        .with_sampler(Sampler::AlwaysOn)
}

fn resource() -> Resource {
    let resource = Resource::new(vec![
        semcov::resource::SERVICE_NAME.string(env!("CARGO_PKG_NAME")),
        semcov::resource::SERVICE_VERSION.string(env!("CARGO_PKG_VERSION")),
    ]);

    let detected = Resource::from_detectors(
        Duration::from_secs(5),
        vec![
            Box::new(sdk::resource::EnvResourceDetector::new()),
            Box::new(sdk::resource::OsResourceDetector),
            Box::new(sdk::resource::ProcessResourceDetector),
        ],
    );

    resource.merge(&detected)
}
