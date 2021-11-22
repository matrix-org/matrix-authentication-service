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

use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use hyper::{header, Server, Version};
use mas_config::RootConfig;
use mas_core::{
    storage::MIGRATOR,
    tasks::{self, TaskQueue},
};
use mas_templates::Templates;
use opentelemetry_http::HeaderExtractor;
use tower::{make::Shared, ServiceBuilder};
use tower_http::{
    compression::CompressionLayer,
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{MakeSpan, OnResponse, TraceLayer},
};
use tracing::{field, info};

use super::RootCommand;

#[derive(Parser, Debug, Default)]
pub(super) struct ServerCommand {
    /// Automatically apply pending migrations
    #[clap(long)]
    migrate: bool,
}

#[derive(Debug, Clone, Default)]
struct OtelMakeSpan;

impl<B> MakeSpan<B> for OtelMakeSpan {
    fn make_span(&mut self, request: &hyper::Request<B>) -> tracing::Span {
        // Extract the context from the headers
        let headers = request.headers();
        let extractor = HeaderExtractor(headers);

        let cx = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&extractor)
        });

        // Attach the context so when the request span is created it gets properly
        // parented
        let _guard = cx.attach();

        let version = match request.version() {
            Version::HTTP_09 => "0.9",
            Version::HTTP_10 => "1.0",
            Version::HTTP_11 => "1.1",
            Version::HTTP_2 => "2.0",
            Version::HTTP_3 => "3.0",
            _ => "",
        };

        let span = tracing::info_span!(
            "request",
            http.method = %request.method(),
            http.target = %request.uri(),
            http.flavor = version,
            http.status_code = field::Empty,
            http.user_agent = field::Empty,
            otel.kind = "server",
            otel.status_code = field::Empty,
        );

        if let Some(user_agent) = headers
            .get(header::USER_AGENT)
            .and_then(|s| s.to_str().ok())
        {
            span.record("http.user_agent", &user_agent);
        }

        span
    }
}

#[derive(Debug, Clone, Default)]
struct OtelOnResponse;

impl<B> OnResponse<B> for OtelOnResponse {
    fn on_response(self, response: &hyper::Response<B>, _latency: Duration, span: &tracing::Span) {
        let s = response.status();
        let status = if s.is_success() {
            "ok"
        } else if s.is_client_error() || s.is_server_error() {
            "error"
        } else {
            "unset"
        };
        span.record("otel.status_code", &status);
        span.record("http.status_code", &s.as_u16());
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C signal handler");

    tracing::info!("Got Ctrl+C, shutting down");
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    // Wait for SIGTERM and SIGINT signals
    // This might panic but should be fine
    let mut term =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM signal handler");
    let mut int = signal(SignalKind::interrupt()).expect("failed to install SIGINT signal handler");

    tokio::select! {
        _ = term.recv() => tracing::info!("Got SIGTERM, shutting down"),
        _ = int.recv() => tracing::info!("Got SIGINT, shutting down"),
    };
}

impl ServerCommand {
    pub async fn run(&self, root: &RootCommand) -> anyhow::Result<()> {
        let config: RootConfig = root.load_config()?;

        let addr: SocketAddr = config.http.address.parse()?;
        let listener = TcpListener::bind(addr)?;

        // Connect to the database
        let pool = config.database.connect().await?;

        if self.migrate {
            info!("Running pending migrations");
            MIGRATOR
                .run(&pool)
                .await
                .context("could not run migrations")?;
        }

        info!("Starting task scheduler");
        let queue = TaskQueue::default();
        queue.recuring(Duration::from_secs(15), tasks::cleanup_expired(&pool));
        queue.start();

        // Load and compile the templates
        let templates =
            Templates::load_from_config(&config.templates).context("could not load templates")?;

        // Start the server
        let root = mas_core::handlers::root(&pool, &templates, &config);

        let warp_service = warp::service(root);

        let service = ServiceBuilder::new()
            // Add high level tracing/logging to all requests
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(OtelMakeSpan)
                    .on_response(OtelOnResponse),
            )
            // Set a timeout
            .timeout(Duration::from_secs(10))
            // Compress responses
            .layer(CompressionLayer::new())
            // Mark the `Authorization` and `Cookie` headers as sensitive so it doesn't show in logs
            .layer(SetSensitiveHeadersLayer::new(vec![
                header::AUTHORIZATION,
                header::COOKIE,
            ]))
            .service(warp_service);

        info!("Listening on http://{}", listener.local_addr().unwrap());

        Server::from_tcp(listener)?
            .serve(Shared::new(service))
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        Ok(())
    }
}
