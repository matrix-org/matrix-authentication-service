// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use itertools::Itertools;
use mas_config::RootConfig;
use mas_handlers::{AppState, HttpClientFactory, MatrixHomeserver};
use mas_listener::{server::Server, shutdown::ShutdownStream};
use mas_matrix_synapse::SynapseConnection;
use mas_router::UrlBuilder;
use mas_storage_pg::MIGRATOR;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use tokio::signal::unix::SignalKind;
use tracing::{info, info_span, warn, Instrument};

use crate::util::{
    database_from_config, mailer_from_config, password_manager_from_config,
    policy_factory_from_config, templates_from_config, watch_templates,
};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Automatically apply pending migrations
    #[arg(long)]
    migrate: bool,

    /// Do not start the task worker
    #[arg(long)]
    no_worker: bool,

    /// Watch for changes for templates on the filesystem
    #[arg(short, long)]
    watch: bool,
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, root: &super::Options) -> anyhow::Result<()> {
        let span = info_span!("cli.run.init").entered();
        let config: RootConfig = root.load_config()?;

        // Connect to the database
        info!("Connecting to the database");
        let pool = database_from_config(&config.database).await?;

        if self.migrate {
            info!("Running pending migrations");
            MIGRATOR
                .run(&pool)
                .instrument(info_span!("db.migrate"))
                .await
                .context("could not run migrations")?;
        }

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let encrypter = config.secrets.encrypter();

        // Load and compile the WASM policies (and fallback to the default embedded one)
        info!("Loading and compiling the policy module");
        let policy_factory = policy_factory_from_config(&config.policy).await?;
        let policy_factory = Arc::new(policy_factory);

        let url_builder = UrlBuilder::new(config.http.public_base.clone());

        // Load and compile the templates
        let templates = templates_from_config(&config.templates, &url_builder).await?;

        if !self.no_worker {
            let mailer = mailer_from_config(&config.email, &templates).await?;
            mailer.test_connection().await?;

            #[allow(clippy::disallowed_methods)]
            let mut rng = thread_rng();
            let worker_name = Alphanumeric.sample_string(&mut rng, 10);

            // Maximum 50 outgoing HTTP requests at a time
            let http_client_factory = HttpClientFactory::new(50);

            info!(worker_name, "Starting task worker");
            let conn = SynapseConnection::new(
                config.matrix.homeserver.clone(),
                config.matrix.endpoint.clone(),
                config.matrix.secret.clone(),
                http_client_factory,
            );
            let monitor = mas_tasks::init(&worker_name, &pool, &mailer, conn);
            // TODO: grab the handle
            tokio::spawn(monitor.run());
        }

        let homeserver = MatrixHomeserver::new(config.matrix.homeserver.clone());

        let listeners_config = config.http.listeners.clone();

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // Maximum 50 outgoing HTTP requests at a time
        let http_client_factory = HttpClientFactory::new(50);

        let conn = SynapseConnection::new(
            config.matrix.homeserver.clone(),
            config.matrix.endpoint.clone(),
            config.matrix.secret.clone(),
            http_client_factory.clone(),
        );

        // Explicitly the config to properly zeroize secret keys
        drop(config);

        // Watch for changes in templates if the --watch flag is present
        if self.watch {
            watch_templates(&templates).await?;
        }

        let graphql_schema = mas_handlers::graphql_schema(&pool, conn);

        let state = AppState {
            pool,
            templates,
            key_store,
            encrypter,
            url_builder,
            homeserver,
            policy_factory,
            graphql_schema,
            http_client_factory,
            password_manager,
        };

        let mut fd_manager = listenfd::ListenFd::from_env();

        let servers: Vec<Server<_>> = listeners_config
            .into_iter()
            .map(|config| {
                // Let's first grab all the listeners
                let listeners = crate::server::build_listeners(&mut fd_manager, &config.binds)?;

                // Load the TLS config
                let tls_config = if let Some(tls_config) = config.tls.as_ref() {
                    let tls_config = crate::server::build_tls_server_config(tls_config)?;
                    Some(Arc::new(tls_config))
                } else {
                    None
                };

                // and build the router
                let router = crate::server::build_router(
                    state.clone(),
                    &config.resources,
                    config.name.as_deref(),
                );

                // Display some informations about where we'll be serving connections
                let proto = if config.tls.is_some() { "https" } else { "http" };
                let addresses= listeners
                    .iter()
                    .map(|listener| {
                        if let Ok(addr) = listener.local_addr() {
                            format!("{proto}://{addr:?}")
                        } else {
                            warn!("Could not get local address for listener, something might be wrong!");
                            format!("{proto}://???")
                        }
                    })
                    .join(", ");

                let additional = if config.proxy_protocol {
                    "(with Proxy Protocol)"
                } else {
                    ""
                };

                info!(
                    "Listening on {addresses} with resources {resources:?} {additional}",
                    resources = &config.resources
                );

                anyhow::Ok(listeners.into_iter().map(move |listener| {
                    let mut server = Server::new(listener, router.clone());
                    if let Some(tls_config) = &tls_config {
                        server = server.with_tls(tls_config.clone());
                    }
                    if config.proxy_protocol {
                        server = server.with_proxy();
                    }
                    server
                }))
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, _>>()?;

        let shutdown = ShutdownStream::default()
            .with_timeout(Duration::from_secs(60))
            .with_signal(SignalKind::terminate())?
            .with_signal(SignalKind::interrupt())?;

        span.exit();

        mas_listener::server::run_servers(servers, shutdown).await;

        Ok(())
    }
}
