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
    filter::LevelFilter, layer::SubscriberExt, reload, util::SubscriberInitExt, EnvFilter, Layer,
    Registry,
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

    // Don't fill the telemetry layer for now, we want to configure it based on the
    // app config, so we need to delay that a bit
    let (telemetry_layer, telemetry_handle) = reload::Layer::new(None);
    // We only want "INFO" level spans to go through OpenTelemetry
    let telemetry_layer = telemetry_layer.with_filter(LevelFilter::INFO);

    // Don't fill the Sentry layer for now, we want to configure it based on the
    // app config, so we need to delay that a bit
    let (sentry_layer, sentry_handle) = reload::Layer::new(None);

    let subscriber = Registry::default()
        .with(sentry_layer)
        .with(telemetry_layer)
        .with(filter_layer)
        .with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Now that logging is set up, we can log stuff, like if the .env file was
    // loaded or not
    match dotenv_path {
        Ok(Some(path)) => tracing::info!(?path, "Loaded environment variables from file"),
        Ok(None) => {}
        Err(err) => tracing::warn!(%err, "failed to load .env file"),
    }

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
    if sentry.is_enabled() {
        let layer = sentry_tracing::layer().event_filter(|md| {
            // All the spans in the handlers module send their data to Sentry themselves, so
            // we only create breadcrumbs for them, instead of full events
            if md.target().starts_with("mas_handlers::") {
                EventFilter::Breadcrumb
            } else {
                sentry_tracing::default_event_filter(md)
            }
        });

        sentry_handle.reload(layer)?;
    }

    // Setup OpenTelemtry tracing and metrics
    let (tracer, _meter) = telemetry::setup(&telemetry_config)
        .await
        .context("failed to setup opentelemetry")?;
    if let Some(tracer) = tracer {
        // Now we can swap out the actual opentelemetry tracing layer
        telemetry_handle.reload(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_tracked_inactivity(false),
        )?;
    }

    // And run the command
    tracing::trace!(?opts, "Running command");
    opts.run().await?;

    Ok(())
}
