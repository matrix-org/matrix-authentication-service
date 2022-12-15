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

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use futures_util::stream::{StreamExt, TryStreamExt};
use itertools::Itertools;
use mas_config::RootConfig;
use mas_handlers::{AppState, HttpClientFactory, MatrixHomeserver};
use mas_listener::{server::Server, shutdown::ShutdownStream};
use mas_router::UrlBuilder;
use mas_storage::MIGRATOR;
use mas_tasks::TaskQueue;
use mas_templates::Templates;
use tokio::signal::unix::SignalKind;
use tracing::{error, info, log::warn};

use crate::util::{mailer_from_config, password_manager_from_config, policy_factory_from_config};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Automatically apply pending migrations
    #[arg(long)]
    migrate: bool,

    /// Watch for changes for templates on the filesystem
    #[arg(short, long)]
    watch: bool,
}

/// Watch for changes in the templates folders
async fn watch_templates(
    client: &watchman_client::Client,
    templates: &Templates,
) -> anyhow::Result<()> {
    use watchman_client::{
        fields::NameOnly,
        pdu::{QueryResult, SubscribeRequest},
        CanonicalPath, SubscriptionData,
    };

    let templates = templates.clone();

    // Find which root we're supposed to watch
    let root = templates.watch_root();

    // For each root, create a subscription
    let resolved = client
        .resolve_root(CanonicalPath::canonicalize(root)?)
        .await?;

    // TODO: we could subscribe to less, properly filter here
    let (subscription, _) = client
        .subscribe::<NameOnly>(&resolved, SubscribeRequest::default())
        .await?;

    // Create a stream out of that subscription
    let fut = futures_util::stream::try_unfold(subscription, |mut sub| async move {
        let next = sub.next().await?;
        anyhow::Ok(Some((next, sub)))
    })
    .try_filter_map(|event| async move {
        match event {
            SubscriptionData::FilesChanged(QueryResult {
                files: Some(files), ..
            }) => {
                let files: Vec<_> = files.into_iter().map(|f| f.name.into_inner()).collect();
                Ok(Some(files))
            }
            _ => Ok(None),
        }
    })
    .for_each(move |files| {
        let templates = templates.clone();
        async move {
            info!(?files, "Files changed, reloading templates");

            templates.clone().reload().await.unwrap_or_else(|err| {
                error!(?err, "Error while reloading templates");
            });
        }
    });

    tokio::spawn(fut);

    Ok(())
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        let config: RootConfig = root.load_config()?;

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
        queue.recuring(Duration::from_secs(15), mas_tasks::cleanup_expired(&pool));
        queue.start();

        // TODO: task queue, key store, encrypter, url builder, http client
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
        let templates = Templates::load(config.templates.path.clone(), url_builder.clone())
            .await
            .context("could not load templates")?;

        let mailer = mailer_from_config(&config.email, &templates).await?;
        mailer.test_connection().await?;

        let homeserver = MatrixHomeserver::new(config.matrix.homeserver.clone());

        let listeners_config = config.http.listeners.clone();

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // Explicitely the config to properly zeroize secret keys
        drop(config);

        // Watch for changes in templates if the --watch flag is present
        if self.watch {
            let client = watchman_client::Connector::new()
                .connect()
                .await
                .context("could not connect to watchman")?;

            watch_templates(&client, &templates)
                .await
                .context("could not watch for templates changes")?;
        }

        let graphql_schema = mas_handlers::graphql_schema(&pool);

        // Maximum 50 outgoing HTTP requests at a time
        let http_client_factory = HttpClientFactory::new(50);

        let state = AppState {
            pool,
            templates,
            key_store,
            encrypter,
            url_builder,
            mailer,
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
                let is_tls = config.tls.is_some();
                let addresses: Vec<String> = listeners
                    .iter()
                    .map(|listener| {
                        let addr = listener.local_addr();
                        let proto = if is_tls { "https" } else { "http" };
                        if let Ok(addr) = addr {
                            format!("{proto}://{addr:?}")
                        } else {
                            warn!(
                            "Could not get local address for listener, something might be wrong!"
                        );
                            format!("{proto}://???")
                        }
                    })
                    .collect();

                let additional = if config.proxy_protocol {
                    "(with Proxy Protocol)"
                } else {
                    ""
                };

                info!(
                    "Listening on {addresses:?} with resources {resources:?} {additional}",
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

        mas_listener::server::run_servers(servers, shutdown).await;

        Ok(())
    }
}
