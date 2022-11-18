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
use mas_email::Mailer;
use mas_handlers::{AppState, MatrixHomeserver};
use mas_http::ServerLayer;
use mas_listener::{server::Server, shutdown::ShutdownStream};
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_storage::MIGRATOR;
use mas_tasks::TaskQueue;
use mas_templates::Templates;
use tokio::signal::unix::SignalKind;
use tracing::{error, info, log::warn};

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

    // Find which roots we're supposed to watch
    let roots = templates.watch_roots().await;
    let mut streams = Vec::new();

    for root in roots {
        // For each root, create a subscription
        let resolved = client
            .resolve_root(CanonicalPath::canonicalize(root)?)
            .await?;

        // TODO: we could subscribe to less, properly filter here
        let (subscription, _) = client
            .subscribe::<NameOnly>(&resolved, SubscribeRequest::default())
            .await?;

        // Create a stream out of that subscription
        let stream = futures_util::stream::try_unfold(subscription, |mut sub| async move {
            let next = sub.next().await?;
            anyhow::Ok(Some((next, sub)))
        });

        streams.push(Box::pin(stream));
    }

    let files_changed_stream =
        futures_util::stream::select_all(streams).try_filter_map(|event| async move {
            match event {
                SubscriptionData::FilesChanged(QueryResult {
                    files: Some(files), ..
                }) => {
                    let files: Vec<_> = files.into_iter().map(|f| f.name.into_inner()).collect();
                    Ok(Some(files))
                }
                _ => Ok(None),
            }
        });

    let fut = files_changed_stream.for_each(move |files| {
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

        // Connect to the mail server
        let mail_transport = config.email.transport.to_transport().await?;
        mail_transport.test_connection().await?;

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

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let encrypter = config.secrets.encrypter();

        // Load and compile the WASM policies (and fallback to the default embedded one)
        info!("Loading and compiling the policy module");
        let policy_file = tokio::fs::File::open(&config.policy.wasm_module)
            .await
            .context("failed to open OPA WASM policy file")?;

        let policy_factory = PolicyFactory::load(
            policy_file,
            config.policy.data.clone().unwrap_or_default(),
            config.policy.register_entrypoint.clone(),
            config.policy.client_registration_entrypoint.clone(),
            config.policy.authorization_grant_entrypoint.clone(),
        )
        .await
        .context("failed to load the policy")?;
        let policy_factory = Arc::new(policy_factory);

        let url_builder = UrlBuilder::new(config.http.public_base.clone());

        // Load and compile the templates
        let templates = Templates::load(
            config.templates.path.clone(),
            config.templates.builtin,
            url_builder.clone(),
        )
        .await
        .context("could not load templates")?;

        let mailer = Mailer::new(
            &templates,
            &mail_transport,
            &config.email.from,
            &config.email.reply_to,
        );

        let homeserver = MatrixHomeserver::new(config.matrix.homeserver.clone());

        let listeners_config = config.http.listeners.clone();

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
                let router = crate::server::build_router(state.clone(), &config.resources)
                    .layer(ServerLayer::new(config.name.clone()))
                    .into_service();

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
