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

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::str_to_string)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use anyhow::Context;
use clap::Parser;
use mas_config::TelemetryConfig;
use sentry_tracing::EventFilter;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

mod commands;
mod server;
mod telemetry;
mod util;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // We're splitting the "fallible" part of main in another function to have a
    // chance to shutdown the telemetry exporters regardless of if there was an
    // error or not
    let res = try_main().await;
    self::telemetry::shutdown();
    res
}

async fn try_main() -> anyhow::Result<()> {
    // Load environment variables from .env files
    // We keep the path to log it afterwards
    let dotenv_path: Result<Option<_>, _> = dotenv::dotenv()
        .map(Some)
        // Display the error if it is something other than the .env file not existing
        .or_else(|e| if e.not_found() { Ok(None) } else { Err(e) });

    // Setup logging
    // This writes logs to stderr
    let (log_writer, _guard) = tracing_appender::non_blocking(std::io::stderr());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(log_writer)
        .with_ansi(atty::is(atty::Stream::Stderr));
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("could not setup logging filter")?;

    // Parse the CLI arguments
    let opts = self::commands::Options::parse();

    // Telemetry config could fail to load, but that's probably OK, since the whole
    // config will be loaded afterwards, and crash if there is a problem.
    // Falling back to default.
    let telemetry_config: TelemetryConfig = opts.load_config().unwrap_or_default();

    // Setup Sentry
    let sentry = sentry::init((
        telemetry_config.sentry.dsn.as_deref(),
        sentry::ClientOptions {
            traces_sample_rate: 1.0,
            auto_session_tracking: true,
            session_mode: sentry::SessionMode::Request,
            ..Default::default()
        },
    ));

    let sentry_layer = sentry.is_enabled().then(|| {
        sentry_tracing::layer().event_filter(|md| {
            // All the spans in the handlers module send their data to Sentry themselves, so
            // we only create breadcrumbs for them, instead of full events
            if md.target().starts_with("mas_handlers::") {
                EventFilter::Breadcrumb
            } else {
                sentry_tracing::default_event_filter(md)
            }
        })
    });

    // Setup OpenTelemetry tracing and metrics
    let (tracer, _meter) = telemetry::setup(&telemetry_config)
        .await
        .context("failed to setup OpenTelemetry")?;

    let telemetry_layer = tracer.map(|tracer| {
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_tracked_inactivity(false)
            .with_exception_fields(true)
            .with_filter(LevelFilter::INFO)
    });

    let subscriber = Registry::default()
        .with(sentry_layer)
        .with(telemetry_layer)
        .with(filter_layer)
        .with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Log about the .env loading
    match dotenv_path {
        Ok(Some(path)) => tracing::info!(?path, "Loaded environment variables from .env file"),
        Ok(None) => {}
        Err(e) => tracing::warn!(?e, "Failed to load .env file"),
    }

    // And run the command
    tracing::trace!(?opts, "Running command");
    opts.run().await?;

    Ok(())
}
