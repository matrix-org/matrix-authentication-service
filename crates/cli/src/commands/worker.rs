// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use clap::Parser;
use mas_config::AppConfig;
use mas_handlers::HttpClientFactory;
use mas_matrix_synapse::SynapseConnection;
use mas_router::UrlBuilder;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use tracing::{info, info_span};

use crate::util::{database_from_config, mailer_from_config, templates_from_config};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, root: &super::Options) -> anyhow::Result<()> {
        let span = info_span!("cli.worker.init").entered();
        let config: AppConfig = root.load_config()?;

        // Connect to the database
        info!("Connecting to the database");
        let pool = database_from_config(&config.database).await?;

        let url_builder =
            UrlBuilder::new(config.http.public_base.clone(), config.http.issuer.clone());

        // Load and compile the templates
        let templates = templates_from_config(&config.templates, &url_builder).await?;

        let mailer = mailer_from_config(&config.email, &templates).await?;
        mailer.test_connection().await?;

        let http_client_factory = HttpClientFactory::new(50);
        let conn = SynapseConnection::new(
            config.matrix.homeserver.clone(),
            config.matrix.endpoint.clone(),
            config.matrix.secret.clone(),
            http_client_factory,
        );

        drop(config);

        #[allow(clippy::disallowed_methods)]
        let mut rng = thread_rng();
        let worker_name = Alphanumeric.sample_string(&mut rng, 10);

        info!(worker_name, "Starting task scheduler");
        let monitor = mas_tasks::init(&worker_name, &pool, &mailer, conn);

        span.exit();

        monitor.run().await?;
        Ok(())
    }
}
