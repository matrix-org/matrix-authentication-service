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
use mas_config::{ConfigurationSection, RootConfig};
use mas_storage::{
    upstream_oauth2::UpstreamOAuthProviderRepository, Repository, RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use tracing::{info, info_span, warn};

use crate::util::database_from_config;

fn map_import_preference(
    config: &mas_config::UpstreamOAuth2ImportPreference,
) -> mas_data_model::UpstreamOAuthProviderImportPreference {
    let action = match &config.action {
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
    };

    mas_data_model::UpstreamOAuthProviderImportPreference { action }
}

fn map_claims_imports(
    config: &mas_config::UpstreamOAuth2ClaimsImports,
) -> mas_data_model::UpstreamOAuthProviderClaimsImports {
    mas_data_model::UpstreamOAuthProviderClaimsImports {
        localpart: config.localpart.as_ref().map(map_import_preference).unwrap_or_default(),
        displayname: config.displayname.as_ref().map(map_import_preference).unwrap_or_default(),
        email: config.email.as_ref().map(map_import_preference).unwrap_or_default(),
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
                let _span =
                    info_span!("cli.config.sync", prune = prune, dry_run = dry_run).entered();

                let clock = SystemClock::default();

                let config: RootConfig = root.load_config()?;
                let encrypter = config.secrets.encrypter();
                let pool = database_from_config(&config.database).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                tracing::info!(
                    prune,
                    dry_run,
                    "Syncing providers and clients defined in config to database"
                );

                let config_ids = config
                    .upstream_oauth2
                    .providers
                    .iter()
                    .map(|p| p.id)
                    .collect::<HashSet<_>>();

                let existing = repo.upstream_oauth_provider().all().await?;
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
                    info!(%provider.id, "Syncing provider");

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

                if dry_run {
                    info!("Dry run, rolling back changes");
                    repo.cancel().await?;
                } else {
                    repo.save().await?;
                }
            }
        }

        Ok(())
    }
}
