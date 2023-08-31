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

use std::collections::HashSet;

use clap::Parser;
use mas_config::{ConfigurationSection, RootConfig, SyncConfig};
use mas_storage::{
    upstream_oauth2::UpstreamOAuthProviderRepository, RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use sqlx::{postgres::PgAdvisoryLock, Acquire};
use tracing::{info, info_span, warn};

use crate::util::database_connection_from_config;

fn map_import_action(
    config: &mas_config::UpstreamOAuth2ImportAction,
) -> mas_data_model::UpstreamOAuthProviderImportAction {
    match config {
        mas_config::UpstreamOAuth2ImportAction::Ignore => {
            mas_data_model::UpstreamOAuthProviderImportAction::Ignore
        }
        mas_config::UpstreamOAuth2ImportAction::Suggest => {
            mas_data_model::UpstreamOAuthProviderImportAction::Suggest
        }
        mas_config::UpstreamOAuth2ImportAction::Force => {
            mas_data_model::UpstreamOAuthProviderImportAction::Force
        }
        mas_config::UpstreamOAuth2ImportAction::Require => {
            mas_data_model::UpstreamOAuthProviderImportAction::Require
        }
    }
}

fn map_import_preference(
    config: &mas_config::UpstreamOAuth2ImportPreference,
) -> mas_data_model::UpstreamOAuthProviderImportPreference {
    mas_data_model::UpstreamOAuthProviderImportPreference {
        action: map_import_action(&config.action),
    }
}

fn map_claims_imports(
    config: &mas_config::UpstreamOAuth2ClaimsImports,
) -> mas_data_model::UpstreamOAuthProviderClaimsImports {
    mas_data_model::UpstreamOAuthProviderClaimsImports {
        localpart: config
            .localpart
            .as_ref()
            .map(map_import_preference)
            .unwrap_or_default(),
        displayname: config
            .displayname
            .as_ref()
            .map(map_import_preference)
            .unwrap_or_default(),
        email: config
            .email
            .as_ref()
            .map(|c| mas_data_model::UpstreamOAuthProviderImportPreference {
                action: map_import_action(&c.action),
            })
            .unwrap_or_default(),
        // XXX: this is a bit ugly
        verify_email: config
            .email
            .as_ref()
            .map(|c| match c.set_email_verification {
                mas_config::UpstreamOAuth2SetEmailVerification::Always => {
                    mas_data_model::UpsreamOAuthProviderSetEmailVerification::Always
                }
                mas_config::UpstreamOAuth2SetEmailVerification::Never => {
                    mas_data_model::UpsreamOAuthProviderSetEmailVerification::Never
                }
                mas_config::UpstreamOAuth2SetEmailVerification::Import => {
                    mas_data_model::UpsreamOAuthProviderSetEmailVerification::Import
                }
            })
            .unwrap_or_default(),
    }
}

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Dump the current config as YAML
    Dump,

    /// Check a config file
    Check,

    /// Generate a new config file
    Generate,

    /// Sync the clients and providers from the config file to the database
    Sync {
        /// Prune elements that are in the database but not in the config file
        /// anymore
        #[clap(long)]
        prune: bool,

        /// Do not actually write to the database
        #[clap(long)]
        dry_run: bool,
    },
}

impl Options {
    pub async fn run(self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Dump => {
                let _span = info_span!("cli.config.dump").entered();

                let config: RootConfig = root.load_config()?;

                serde_yaml::to_writer(std::io::stdout(), &config)?;
            }

            SC::Check => {
                let _span = info_span!("cli.config.check").entered();

                let _config: RootConfig = root.load_config()?;
                info!(path = ?root.config, "Configuration file looks good");
            }

            SC::Generate => {
                let _span = info_span!("cli.config.generate").entered();

                // XXX: we should disallow SeedableRng::from_entropy
                let rng = rand_chacha::ChaChaRng::from_entropy();
                let config = RootConfig::load_and_generate(rng).await?;

                serde_yaml::to_writer(std::io::stdout(), &config)?;
            }

            SC::Sync { prune, dry_run } => {
                sync(root, prune, dry_run).await?;
            }
        }

        Ok(())
    }
}

#[tracing::instrument(name = "cli.config.sync", skip(root), err(Debug))]
async fn sync(root: &super::Options, prune: bool, dry_run: bool) -> anyhow::Result<()> {
    // XXX: we should disallow SeedableRng::from_entropy
    let clock = SystemClock::default();

    let config: SyncConfig = root.load_config()?;
    let encrypter = config.secrets.encrypter();
    // Grab a connection to the database
    let mut conn = database_connection_from_config(&config.database).await?;
    // Start a transaction
    let txn = conn.begin().await?;

    // Grab a lock within the transaction
    tracing::info!("Acquiring config lock");
    let lock = PgAdvisoryLock::new("MAS config sync");
    let lock = lock.acquire(txn).await?;

    // Create a repository from the connection with the lock
    let mut repo = PgRepository::from_conn(lock);

    tracing::info!(
        prune,
        dry_run,
        "Syncing providers and clients defined in config to database"
    );

    {
        let _span = info_span!("cli.config.sync.providers").entered();
        let config_ids = config
            .upstream_oauth2
            .providers
            .iter()
            .map(|p| p.id)
            .collect::<HashSet<_>>();

        let existing = repo.upstream_oauth_provider().all().await?;
        let existing_ids = existing.iter().map(|p| p.id).collect::<HashSet<_>>();
        let to_delete = existing.into_iter().filter(|p| !config_ids.contains(&p.id));
        if prune {
            for provider in to_delete {
                info!(%provider.id, "Deleting provider");

                if dry_run {
                    continue;
                }

                repo.upstream_oauth_provider().delete(provider).await?;
            }
        } else {
            let len = to_delete.count();
            match len {
                0 => {},
                1 => warn!("A provider in the database is not in the config. Run with `--prune` to delete it."),
                n => warn!("{n} providers in the database are not in the config. Run with `--prune` to delete them."),
            }
        }

        for provider in config.upstream_oauth2.providers {
            if existing_ids.contains(&provider.id) {
                info!(%provider.id, "Updating provider");
            } else {
                info!(%provider.id, "Adding provider");
            }

            if dry_run {
                continue;
            }

            let encrypted_client_secret = provider
                .client_secret()
                .map(|client_secret| encrypter.encrypt_to_string(client_secret.as_bytes()))
                .transpose()?;
            let client_auth_method = provider.client_auth_method();
            let client_auth_signing_alg = provider.client_auth_signing_alg();

            repo.upstream_oauth_provider()
                .upsert(
                    &clock,
                    provider.id,
                    provider.issuer,
                    provider.scope.parse()?,
                    client_auth_method,
                    client_auth_signing_alg,
                    provider.client_id,
                    encrypted_client_secret,
                    map_claims_imports(&provider.claims_imports),
                )
                .await?;
        }
    }

    {
        let _span = info_span!("cli.config.sync.clients").entered();
        let config_ids = config
            .clients
            .iter()
            .map(|c| c.client_id)
            .collect::<HashSet<_>>();

        let existing = repo.oauth2_client().all_static().await?;
        let existing_ids = existing.iter().map(|p| p.id).collect::<HashSet<_>>();
        let to_delete = existing.into_iter().filter(|p| !config_ids.contains(&p.id));
        if prune {
            for client in to_delete {
                info!(client.id = %client.client_id, "Deleting client");

                if dry_run {
                    continue;
                }

                repo.oauth2_client().delete(client).await?;
            }
        } else {
            let len = to_delete.count();
            match len {
                0 => {},
                1 => warn!("A static client in the database is not in the config. Run with `--prune` to delete it."),
                n => warn!("{n} static clients in the database are not in the config. Run with `--prune` to delete them."),
            }
        }

        for client in config.clients.iter() {
            if existing_ids.contains(&client.client_id) {
                info!(client.id = %client.client_id, "Updating client");
            } else {
                info!(client.id = %client.client_id, "Adding client");
            }

            if dry_run {
                continue;
            }

            let client_secret = client.client_secret();
            let client_auth_method = client.client_auth_method();
            let jwks = client.jwks();
            let jwks_uri = client.jwks_uri();

            // TODO: should be moved somewhere else
            let encrypted_client_secret = client_secret
                .map(|client_secret| encrypter.encrypt_to_string(client_secret.as_bytes()))
                .transpose()?;

            repo.oauth2_client()
                .upsert_static(
                    client.client_id,
                    client_auth_method,
                    encrypted_client_secret,
                    jwks.cloned(),
                    jwks_uri.cloned(),
                    client.redirect_uris.clone(),
                )
                .await?;
        }
    }

    // Get the lock and release it to commit the transaction
    let lock = repo.into_inner();
    let txn = lock.release_now().await?;
    if dry_run {
        info!("Dry run, rolling back changes");
        txn.rollback().await?;
    } else {
        txn.commit().await?;
    }
    Ok(())
}
