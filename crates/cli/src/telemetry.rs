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

use std::time::Duration;

use futures::stream::{Stream, StreamExt};
use mas_config::{MetricsConfig, TelemetryConfig, TracingConfig};
use opentelemetry::{
    global,
    propagation::TextMapPropagator,
    sdk::{
        self,
        propagation::{BaggagePropagator, TextMapCompositePropagator, TraceContextPropagator},
        trace::Tracer,
        Resource,
    },
};
use opentelemetry_semantic_conventions as semcov;

pub fn setup(config: &TelemetryConfig) -> anyhow::Result<Option<Tracer>> {
    global::set_error_handler(|e| tracing::error!("{}", e))?;
    global::set_text_map_propagator(propagator());

    let tracer = tracer(&config.tracing)?;
    meter(&config.metrics)?;
    Ok(tracer)
}

pub fn shutdown() {
    global::shutdown_tracer_provider();
}

fn propagator() -> impl TextMapPropagator {
    // TODO: make this configurable
    let baggage_propagator = BaggagePropagator::new();
    let trace_context_propagator = TraceContextPropagator::new();

    TextMapCompositePropagator::new(vec![
        Box::new(baggage_propagator),
        Box::new(trace_context_propagator),
    ])
}

#[cfg(feature = "otlp")]
fn otlp_tracer(endpoint: &Option<url::Url>) -> anyhow::Result<Tracer> {
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
fn otlp_tracer(_endpoint: &Option<url::Url>) -> anyhow::Result<Tracer> {
    anyhow::bail!("The service was compiled without OTLP exporter support, but config exports traces via OTLP.")
}

fn stdout_tracer() -> Tracer {
    sdk::export::trace::stdout::new_pipeline()
        .with_pretty_print(true)
        .with_trace_config(trace_config())
        .install_simple()
}

fn tracer(config: &TracingConfig) -> anyhow::Result<Option<Tracer>> {
    let tracer = match config {
        TracingConfig::None => return Ok(None),
        TracingConfig::Stdout => stdout_tracer(),
        TracingConfig::Otlp { endpoint } => otlp_tracer(endpoint)?,
    };

    Ok(Some(tracer))
}

fn interval(duration: Duration) -> impl Stream<Item = tokio::time::Instant> {
    // Skip first immediate tick from tokio
    opentelemetry::util::tokio_interval_stream(duration).skip(1)
}

#[cfg(feature = "otlp")]
fn otlp_meter(endpoint: &Option<url::Url>) -> anyhow::Result<()> {
    use opentelemetry_otlp::WithExportConfig;

    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }

    opentelemetry_otlp::new_pipeline()
        .metrics(tokio::spawn, interval)
        .with_exporter(exporter)
        .with_aggregator_selector(sdk::metrics::selectors::simple::Selector::Exact)
        .build()?;

    Ok(())
}

#[cfg(not(feature = "otlp"))]
fn otlp_meter(_endpoint: &Option<url::Url>) -> anyhow::Result<()> {
    anyhow::bail!("The service was compiled without OTLP exporter support, but config exports metrics via OTLP.")
}

fn stdout_meter() {
    sdk::export::metrics::stdout(tokio::spawn, interval)
        .with_pretty_print(true)
        .init();
}

fn meter(config: &MetricsConfig) -> anyhow::Result<()> {
    match config {
        MetricsConfig::None => {}
        MetricsConfig::Stdout => stdout_meter(),
        MetricsConfig::Otlp { endpoint } => otlp_meter(endpoint)?,
    };

    Ok(())
}

fn trace_config() -> sdk::trace::Config {
    sdk::trace::config().with_resource(resource())
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
