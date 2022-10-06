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
use futures_util::{
    future::FutureExt,
    stream::{StreamExt, TryStreamExt},
};
use hyper::Server;
use mas_config::RootConfig;
use mas_email::Mailer;
use mas_handlers::{AppState, MatrixHomeserver};
use mas_http::ServerLayer;
use mas_listener::{maybe_tls::MaybeTlsAcceptor, proxy_protocol::MaybeProxyAcceptor};
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_storage::MIGRATOR;
use mas_tasks::TaskQueue;
use mas_templates::Templates;
use tokio::io::AsyncRead;
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
        let mut policy: Box<dyn AsyncRead + std::marker::Unpin> =
            if let Some(path) = &config.policy.wasm_module {
                Box::new(
                    tokio::fs::File::open(path)
                        .await
                        .context("failed to open OPA WASM policy file")?,
                )
            } else {
                Box::new(mas_policy::default_wasm_policy())
            };

        let policy_factory = PolicyFactory::load(
            &mut policy,
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

        let state = Arc::new(AppState {
            pool,
            templates,
            key_store,
            encrypter,
            url_builder,
            mailer,
            homeserver,
            policy_factory,
        });

        let signal = shutdown_signal().shared();
        let shutdown_signal = signal.clone();

        let mut fd_manager = listenfd::ListenFd::from_env();
        let listeners = listeners_config.into_iter().map(|listener_config| {
            // Let's first grab all the listeners in a synchronous manner
            let listeners = crate::server::build_listeners(&mut fd_manager, &listener_config.binds);

            Ok((listener_config, listeners?))
        });

        // Now that we have the listeners ready, we can do the rest concurrently
        futures_util::stream::iter(listeners)
            .try_for_each_concurrent(None, move |(config, listeners)| {
                let signal = signal.clone();

                let is_tls = config.tls.is_some();
                let addresses: Vec<String> = listeners.iter().map(|listener| {
                    let addr = listener.local_addr();
                    let proto = if is_tls { "https" } else { "http" };
                    if let Ok(addr) = addr {
                        format!("{proto}://{addr:?}")
                    } else {
                        warn!("Could not get local address for listener, something might be wrong!");
                        format!("{proto}://???")
                    }
                }).collect();

                let additional = if config.proxy_protocol { "(with Proxy Protocol)" } else { "" };

                info!("Listening on {addresses:?} with resources {resources:?} {additional}", resources = &config.resources);

                let router = crate::server::build_router(&state, &config.resources).layer(ServerLayer::new(config.name.clone()));

                async move {
                    let tls_config = if let Some(tls_config) = config.tls.as_ref() {
                        let tls_config = crate::server::build_tls_server_config(tls_config).await?;
                        Some(Arc::new(tls_config))
                    } else { None };

                    futures_util::stream::iter(listeners)
                        .map(Ok)
                        .try_for_each_concurrent(None, move |listener| {
                            let listener = MaybeTlsAcceptor::new(tls_config.clone(), listener);
                            let listener = MaybeProxyAcceptor::new(listener, config.proxy_protocol);

                            Server::builder(listener)
                                .serve(router.clone().into_make_service())
                                .with_graceful_shutdown(signal.clone())
                        })
                        .await?;

                    anyhow::Ok(())
                }
            })
            .await?;

        // This ensures we're running, even if no listener are setup
        // This is useful for only running the task runner
        shutdown_signal.await;

        Ok(())
    }
}
