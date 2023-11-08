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

use std::time::Duration;

use anyhow::Context as _;
use hyper::{header::CONTENT_TYPE, Body, Response};
use mas_config::{
    JaegerExporterProtocolConfig, MetricsExporterConfig, Propagator, TelemetryConfig,
    TracingExporterConfig,
};
use opentelemetry::{global, propagation::TextMapPropagator, trace::TracerProvider as _};
use opentelemetry_jaeger::Propagator as JaegerPropagator;
use opentelemetry_otlp::MetricsExporterBuilder;
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::{
    self,
    metrics::{
        reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
        ManualReader, MeterProvider, PeriodicReader,
    },
    propagation::{BaggagePropagator, TextMapCompositePropagator, TraceContextPropagator},
    trace::{Sampler, Tracer, TracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions as semcov;
use opentelemetry_zipkin::{B3Encoding, Propagator as ZipkinPropagator};
use prometheus::Registry;
use tokio::sync::OnceCell;
use url::Url;

static METER_PROVIDER: OnceCell<MeterProvider> = OnceCell::const_new();
static PROMETHEUS_REGISTRY: OnceCell<Registry> = OnceCell::const_new();

pub async fn setup(config: &TelemetryConfig) -> anyhow::Result<Option<Tracer>> {
    global::set_error_handler(|e| tracing::error!("{}", e))?;
    let propagator = propagator(&config.tracing.propagators);

    // The CORS filter needs to know what headers it should whitelist for
    // CORS-protected requests.
    mas_http::set_propagator(&propagator);
    global::set_text_map_propagator(propagator);

    let tracer = tracer(&config.tracing.exporter)
        .await
        .context("Failed to configure traces exporter")?;

    init_meter(&config.metrics.exporter).context("Failed to configure metrics exporter")?;

    Ok(tracer)
}

pub fn shutdown() {
    global::shutdown_tracer_provider();

    if let Some(meter_provider) = METER_PROVIDER.get() {
        meter_provider.shutdown().unwrap();
    }
}

fn match_propagator(propagator: Propagator) -> Box<dyn TextMapPropagator + Send + Sync> {
    use Propagator as P;
    match propagator {
        P::TraceContext => Box::new(TraceContextPropagator::new()),
        P::Baggage => Box::new(BaggagePropagator::new()),
        P::Jaeger => Box::new(JaegerPropagator::new()),
        P::B3 => Box::new(ZipkinPropagator::with_encoding(B3Encoding::SingleHeader)),
        P::B3Multi => Box::new(ZipkinPropagator::with_encoding(B3Encoding::MultipleHeader)),
    }
}

fn propagator(propagators: &[Propagator]) -> impl TextMapPropagator {
    let propagators = propagators.iter().copied().map(match_propagator).collect();

    TextMapCompositePropagator::new(propagators)
}

async fn http_client() -> anyhow::Result<impl opentelemetry_http::HttpClient + 'static> {
    let client = mas_http::make_untraced_client()
        .await
        .context("Failed to build HTTP client used by telemetry exporter")?;
    let client =
        opentelemetry_http::hyper::HyperClient::new_with_timeout(client, Duration::from_secs(30));
    Ok(client)
}

fn stdout_tracer_provider() -> TracerProvider {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    TracerProvider::builder()
        .with_simple_exporter(exporter)
        .build()
}

fn otlp_tracer(endpoint: Option<&Url>) -> anyhow::Result<Tracer> {
    use opentelemetry_otlp::WithExportConfig;

    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(trace_config())
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to configure OTLP trace exporter")?;

    Ok(tracer)
}

fn jaeger_agent_tracer_provider(host: &str, port: u16) -> anyhow::Result<TracerProvider> {
    let pipeline = opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_trace_config(trace_config())
        .with_endpoint(format!("{host}:{port}"));

    let tracer_provider = pipeline
        .build_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to configure Jaeger agent exporter")?;

    Ok(tracer_provider)
}

async fn jaeger_collector_tracer_provider(
    endpoint: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<TracerProvider> {
    let http_client = http_client().await?;
    let mut pipeline = opentelemetry_jaeger::new_collector_pipeline()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_trace_config(trace_config())
        .with_http_client(http_client)
        .with_endpoint(endpoint);

    if let Some(username) = username {
        pipeline = pipeline.with_username(username);
    }

    if let Some(password) = password {
        pipeline = pipeline.with_password(password);
    }

    let tracer_provider = pipeline
        .build_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to configure Jaeger collector exporter")?;

    Ok(tracer_provider)
}

async fn zipkin_tracer(collector_endpoint: &Option<Url>) -> anyhow::Result<Tracer> {
    let http_client = http_client().await?;

    let mut pipeline = opentelemetry_zipkin::new_pipeline()
        .with_http_client(http_client)
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_trace_config(trace_config());

    if let Some(collector_endpoint) = collector_endpoint {
        pipeline = pipeline.with_collector_endpoint(collector_endpoint.as_str());
    }

    let tracer = pipeline
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to configure Zipkin exporter")?;

    Ok(tracer)
}

async fn tracer(config: &TracingExporterConfig) -> anyhow::Result<Option<Tracer>> {
    let tracer_provider = match config {
        TracingExporterConfig::None => return Ok(None),
        TracingExporterConfig::Stdout => stdout_tracer_provider(),
        TracingExporterConfig::Otlp { endpoint } => {
            // The OTLP exporter already creates a tracer and installs it
            return Ok(Some(otlp_tracer(endpoint.as_ref())?));
        }
        TracingExporterConfig::Jaeger(JaegerExporterProtocolConfig::UdpThriftCompact {
            agent_host,
            agent_port,
        }) => jaeger_agent_tracer_provider(agent_host, *agent_port)?,
        TracingExporterConfig::Jaeger(JaegerExporterProtocolConfig::HttpThriftBinary {
            endpoint,
            username,
            password,
        }) => {
            jaeger_collector_tracer_provider(endpoint, username.as_deref(), password.as_deref())
                .await?
        }
        TracingExporterConfig::Zipkin { collector_endpoint } => {
            // The Zipkin exporter already creates a tracer and installs it
            return Ok(Some(zipkin_tracer(collector_endpoint).await?));
        }
    };

    let tracer = tracer_provider.versioned_tracer(
        env!("CARGO_PKG_NAME"),
        Some(env!("CARGO_PKG_VERSION")),
        Some(semcov::SCHEMA_URL),
        None,
    );
    global::set_tracer_provider(tracer_provider);

    Ok(Some(tracer))
}

fn otlp_metric_reader(endpoint: Option<&url::Url>) -> anyhow::Result<PeriodicReader> {
    use opentelemetry_otlp::WithExportConfig;

    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }

    let exporter = MetricsExporterBuilder::from(exporter).build_metrics_exporter(
        Box::new(DefaultTemporalitySelector::new()),
        Box::new(DefaultAggregationSelector::new()),
    )?;

    Ok(PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build())
}

fn stdout_metric_reader() -> PeriodicReader {
    let exporter = opentelemetry_stdout::MetricsExporter::default();
    PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build()
}

type PromServiceFuture = std::future::Ready<Result<Response<Body>, std::convert::Infallible>>;

#[allow(clippy::needless_pass_by_value)]
fn prometheus_service_fn<T>(_req: T) -> PromServiceFuture {
    use prometheus::{Encoder, TextEncoder};

    let response = if let Some(registry) = PROMETHEUS_REGISTRY.get() {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = registry.gather();

        // That shouldn't panic, unless we're constructing invalid labels
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(200)
            .header(CONTENT_TYPE, encoder.format_type())
            .body(Body::from(buffer))
            .unwrap()
    } else {
        Response::builder()
            .status(500)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("Prometheus exporter was not enabled in config"))
            .unwrap()
    };

    std::future::ready(Ok(response))
}

pub fn prometheus_service<T>() -> tower::util::ServiceFn<fn(T) -> PromServiceFuture> {
    if !PROMETHEUS_REGISTRY.initialized() {
        tracing::warn!("A Prometheus resource was mounted on a listener, but the Prometheus exporter was not setup in the config");
    }

    tower::service_fn(prometheus_service_fn as _)
}

fn prometheus_metric_reader() -> anyhow::Result<PrometheusExporter> {
    let registry = Registry::new();
    PROMETHEUS_REGISTRY.set(registry.clone())?;

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry)
        .without_scope_info()
        .build()?;

    Ok(exporter)
}

fn init_meter(config: &MetricsExporterConfig) -> anyhow::Result<()> {
    let meter_provider_builder = MeterProvider::builder();
    let meter_provider_builder = match config {
        MetricsExporterConfig::None => meter_provider_builder.with_reader(ManualReader::default()),
        MetricsExporterConfig::Stdout => meter_provider_builder.with_reader(stdout_metric_reader()),
        MetricsExporterConfig::Otlp { endpoint } => {
            meter_provider_builder.with_reader(otlp_metric_reader(endpoint.as_ref())?)
        }
        MetricsExporterConfig::Prometheus => {
            meter_provider_builder.with_reader(prometheus_metric_reader()?)
        }
    };

    let meter_provider = meter_provider_builder.with_resource(resource()).build();

    METER_PROVIDER.set(meter_provider.clone())?;
    global::set_meter_provider(meter_provider.clone());

    Ok(())
}

fn trace_config() -> opentelemetry_sdk::trace::Config {
    opentelemetry_sdk::trace::config()
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
            Box::new(opentelemetry_sdk::resource::EnvResourceDetector::new()),
            Box::new(opentelemetry_sdk::resource::OsResourceDetector),
            Box::new(opentelemetry_sdk::resource::ProcessResourceDetector),
            Box::new(opentelemetry_sdk::resource::TelemetryResourceDetector),
        ],
    );

    resource.merge(&detected)
}
