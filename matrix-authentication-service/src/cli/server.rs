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

use anyhow::Context;
use clap::Clap;

use super::RootCommand;
use crate::{config::RootConfig, state::State};

#[derive(Clap, Debug, Default)]
pub(super) struct ServerCommand;

impl ServerCommand {
    pub async fn run(&self, root: &RootCommand) -> anyhow::Result<()> {
        let config: RootConfig = root.load_config()?;

        // Connect to the database
        let pool = config.database.connect().await?;

        // Load and compile the templates
        let templates = crate::templates::load().context("could not load templates")?;

        // Create the shared state
        let state = State::new(config, templates, pool);
        state
            .storage()
            .load_static_clients(&state.config().oauth2.clients)
            .await;

        // Start the server
        let address = state.config().http.address.clone();
        let mut app = tide::with_state(state);
        app.with(tide_tracing::TraceMiddleware::new());
        crate::handlers::install(&mut app);
        app.listen(address)
            .await
            .context("could not start server")?;

        Ok(())
    }
}
