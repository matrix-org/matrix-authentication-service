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

use anyhow::Context;
use tracing::{info_span, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

mod config;
mod csrf;
mod handlers;
mod middlewares;
mod state;
mod storage;
mod templates;

use self::config::RootConfig;
use self::state::State;
use self::storage::MIGRATOR;

#[async_std::main]
async fn main() -> tide::Result<()> {
    // Setup logging & tracing
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Loading the config
    let config = RootConfig::load().context("could not load config")?;

    // Connect to the database
    let pool = config
        .database
        .connect()
        .await
        .context("could not connect to database")?;

    // Load and compile the templates
    let templates = self::templates::load().context("could not load templates")?;

    // Create the shared state
    let state = State::new(config, templates, pool);
    state
        .storage()
        .load_static_clients(&state.config().oauth2.clients)
        .await;

    // Run pending migrations
    // TODO: make this a separate command
    MIGRATOR
        .run(state.storage().pool())
        .instrument(info_span!("migrations"))
        .await
        .context("could not run migrations")?;

    // Start the server
    let address = state.config().http.address.clone();
    let mut app = tide::with_state(state);
    app.with(tide_tracing::TraceMiddleware::new());
    self::handlers::install(&mut app);
    app.listen(address)
        .await
        .context("could not start server")?;
    Ok(())
}
