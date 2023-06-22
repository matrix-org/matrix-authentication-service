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
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, Repository, RepositoryAccess};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use tracing::{info, info_span, warn};

use crate::util::database_from_config;

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
                let _span = info_span!("cli.config.sync").entered();

                let config: RootConfig = root.load_config()?;
                let pool = database_from_config(&config.database).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                tracing::info!(
                    prune,
                    dry_run,
                    "Syncing providers and clients defined in config to database"
                );

                let existing = repo.upstream_oauth_provider().all().await?;

                let existing_ids = existing.iter().map(|p| p.id).collect::<HashSet<_>>();
                let config_ids = config
                    .upstream_oauth2
                    .providers
                    .iter()
                    .map(|p| p.id)
                    .collect::<HashSet<_>>();

                let needs_pruning = existing_ids.difference(&config_ids).collect::<Vec<_>>();
                if prune {
                    for id in needs_pruning {
                        info!(provider.id = %id, "Deleting provider");
                    }
                } else if !needs_pruning.is_empty() {
                    warn!(
                        "{} provider(s) in the database are not in the config. Run with `--prune` to delete them.",
                        needs_pruning.len()
                    );
                }

                for provider in config.upstream_oauth2.providers {
                    if existing_ids.contains(&provider.id) {
                        info!(%provider.id, "Updating provider");
                    } else {
                        info!(%provider.id, "Adding provider");
                    }
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
