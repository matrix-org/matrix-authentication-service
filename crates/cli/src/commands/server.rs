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

use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use futures_util::stream::{StreamExt, TryStreamExt};
use hyper::Server;
use mas_config::RootConfig;
use mas_email::Mailer;
use mas_handlers::{AppState, MatrixHomeserver};
use mas_http::ServerLayer;
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_storage::MIGRATOR;
use mas_tasks::TaskQueue;
use mas_templates::Templates;
use tokio::io::AsyncRead;
use tracing::{error, info};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Automatically apply pending migrations
    #[clap(long)]
    migrate: bool,

    /// Watch for changes for templates on the filesystem
    #[clap(short, long)]
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
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        let config: RootConfig = root.load_config()?;

        let addr: SocketAddr = config
            .http
            .address
            .parse()
            .context("could not parse listener address")?;
        let listener = TcpListener::bind(addr).context("could not bind address")?;

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

        // Load and compile the templates
        let templates = Templates::load(config.templates.path.clone(), config.templates.builtin)
            .await
            .context("could not load templates")?;

        let mailer = Mailer::new(
            &templates,
            &mail_transport,
            &config.email.from,
            &config.email.reply_to,
        );

        let url_builder = UrlBuilder::new(config.http.public_base.clone());

        let static_files = mas_static_files::service(&config.http.web_root);

        let homeserver = MatrixHomeserver::new(config.matrix.homeserver.clone());

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

        let state = AppState {
            pool,
            templates,
            key_store,
            encrypter,
            url_builder,
            mailer,
            homeserver,
            policy_factory,
        };

        let router = mas_handlers::router(state)
            .fallback_service(static_files)
            .layer(ServerLayer::default());

        info!("Listening on http://{}", listener.local_addr().unwrap());

        Server::from_tcp(listener)?
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        Ok(())
    }
}
