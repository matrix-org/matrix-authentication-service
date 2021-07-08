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

#[async_std::main]
async fn main() -> tide::Result<()> {
    // Setup logging & tracing
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    subscriber.try_init()?;

    // Loading the config
    let config = RootConfig::load()?;

    // Load and compile the templates
    let templates = self::templates::load()?;

    // Create the shared state
    let state = State::new(config, templates);
    state
        .storage()
        .load_static_clients(&state.config().oauth2.clients)
        .await;

    // Start the server
    let address = state.config().http.address.clone();
    let mut app = tide::with_state(state);
    app.with(tide_tracing::TraceMiddleware::new());
    self::handlers::install(&mut app);
    app.listen(address).await?;
    Ok(())
}
