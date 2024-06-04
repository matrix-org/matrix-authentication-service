// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use itertools::Itertools;
use mas_config::{AppConfig, ClientsConfig, ConfigurationSection, UpstreamOAuth2Config};
use mas_handlers::{ActivityTracker, CookieManager, HttpClientFactory, MetadataCache};
use mas_listener::{server::Server, shutdown::ShutdownStream};
use mas_matrix_synapse::SynapseConnection;
use mas_router::UrlBuilder;
use mas_storage::SystemClock;
use mas_storage_pg::MIGRATOR;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use sqlx::migrate::Migrate;
use tokio::signal::unix::SignalKind;
use tracing::{info, info_span, warn, Instrument};

use crate::{
    app_state::AppState,
    util::{
        database_pool_from_config, mailer_from_config, password_manager_from_config,
        policy_factory_from_config, register_sighup, site_config_from_config,
        templates_from_config,
    },
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Do not apply pending database migrations on start
    #[arg(long)]
    no_migrate: bool,

    /// DEPRECATED: default is to apply pending migrations, use `--no-migrate`
    /// to disable
    #[arg(long, hide = true)]
    migrate: bool,

    /// Do not start the task worker
    #[arg(long)]
    no_worker: bool,

    /// Do not sync the configuration with the database
    #[arg(long)]
    no_sync: bool,
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<()> {
        let span = info_span!("cli.run.init").entered();
        let config = AppConfig::extract(figment)?;

        if self.migrate {
            warn!("The `--migrate` flag is deprecated and will be removed in a future release. Please use `--no-migrate` to disable automatic migrations on startup.");
        }

        // Connect to the database
        info!("Connecting to the database");
        let pool = database_pool_from_config(&config.database).await?;

        if self.no_migrate {
            // Check that we applied all the migrations
            let mut conn = pool.acquire().await?;
            let applied = conn.list_applied_migrations().await?;
            let applied: BTreeSet<_> = applied.into_iter().map(|m| m.version).collect();
            let has_missing_migrations = MIGRATOR.iter().any(|m| !applied.contains(&m.version));
            if has_missing_migrations {
                // Refuse to start if there are pending migrations
                return Err(anyhow::anyhow!("The server is running with `--no-migrate` but there are pending. Please run them first with `mas-cli database migrate`, or omit the `--no-migrate` flag to apply them automatically on startup."));
            }
        } else {
            info!("Running pending database migrations");
            MIGRATOR
                .run(&pool)
                .instrument(info_span!("db.migrate"))
                .await
                .context("could not run database migrations")?;
        }

        let encrypter = config.secrets.encrypter();

        if self.no_sync {
            info!("Skipping configuration sync");
        } else {
            // Sync the configuration with the database
            let mut conn = pool.acquire().await?;
            let clients_config = ClientsConfig::extract(figment)?;
            let upstream_oauth2_config = UpstreamOAuth2Config::extract(figment)?;

            crate::sync::config_sync(
                upstream_oauth2_config,
                clients_config,
                &mut conn,
                &encrypter,
                &SystemClock::default(),
                false,
                false,
            )
            .await?;
        }

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let cookie_manager =
            CookieManager::derive_from(config.http.public_base.clone(), &config.secrets.encryption);

        // Load and compile the WASM policies (and fallback to the default embedded one)
        info!("Loading and compiling the policy module");
        let policy_factory = policy_factory_from_config(&config.policy).await?;
        let policy_factory = Arc::new(policy_factory);

        let url_builder = UrlBuilder::new(
            config.http.public_base.clone(),
            config.http.issuer.clone(),
            None,
        );

        // Load the site configuration
        let site_config = site_config_from_config(
            &config.branding,
            &config.matrix,
            &config.experimental,
            &config.passwords,
            &config.captcha,
        )?;

        // Load and compile the templates
        let templates =
            templates_from_config(&config.templates, &site_config, &url_builder).await?;

        let http_client_factory = HttpClientFactory::new();

        let homeserver_connection = SynapseConnection::new(
            config.matrix.homeserver.clone(),
            config.matrix.endpoint.clone(),
            config.matrix.secret.clone(),
            http_client_factory.clone(),
        );

        if !self.no_worker {
            let mailer = mailer_from_config(&config.email, &templates)?;
            mailer.test_connection().await?;

            #[allow(clippy::disallowed_methods)]
            let mut rng = thread_rng();
            let worker_name = Alphanumeric.sample_string(&mut rng, 10);

            info!(worker_name, "Starting task worker");
            let monitor =
                mas_tasks::init(&worker_name, &pool, &mailer, homeserver_connection.clone())
                    .await?;
            // TODO: grab the handle
            tokio::spawn(monitor.run());
        }

        let listeners_config = config.http.listeners.clone();

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // The upstream OIDC metadata cache
        let metadata_cache = MetadataCache::new();

        // Initialize the activity tracker
        // Activity is flushed every minute
        let activity_tracker = ActivityTracker::new(pool.clone(), Duration::from_secs(60));
        let trusted_proxies = config.http.trusted_proxies.clone();

        // Explicitly the config to properly zeroize secret keys
        drop(config);

        // Listen for SIGHUP
        register_sighup(&templates, &activity_tracker)?;

        let graphql_schema = mas_handlers::graphql_schema(
            &pool,
            &policy_factory,
            homeserver_connection.clone(),
            site_config.clone(),
            password_manager.clone(),
        );

        let state = {
            let mut s = AppState {
                pool,
                templates,
                key_store,
                metadata_cache,
                cookie_manager,
                encrypter,
                url_builder,
                homeserver_connection,
                policy_factory,
                graphql_schema,
                http_client_factory,
                password_manager,
                site_config,
                activity_tracker,
                trusted_proxies,
                conn_acquisition_histogram: None,
            };
            s.init_metrics()?;
            // XXX: this might panic
            s.init_metadata_cache().await;
            s
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
                    config.prefix.as_deref(),
                    config.name.as_deref(),
                );


                // Display some informations about where we'll be serving connections
                let proto = if config.tls.is_some() { "https" } else { "http" };
                let prefix = config.prefix.unwrap_or_default();
                let addresses= listeners
                    .iter()
                    .map(|listener| {
                        if let Ok(addr) = listener.local_addr() {
                            format!("{proto}://{addr:?}{prefix}")
                        } else {
                            warn!("Could not get local address for listener, something might be wrong!");
                            format!("{proto}://???{prefix}")
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

        state.activity_tracker.shutdown().await;

        Ok(())
    }
}
