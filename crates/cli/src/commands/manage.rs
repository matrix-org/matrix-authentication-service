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

use argon2::Argon2;
use clap::Parser;
use mas_config::{DatabaseConfig, RootConfig};
use mas_storage::{
    oauth2::client::{insert_client_from_config, lookup_client, truncate_clients},
    user::{
        lookup_user_by_username, lookup_user_email, mark_user_email_as_verified, register_user,
    },
    Clock,
};
use rand::SeedableRng;
use tracing::{info, warn};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Register a new user
    Register { username: String, password: String },

    /// List active users
    Users,

    /// Mark email address as verified
    VerifyEmail { username: String, email: String },

    /// Import clients from config
    ImportClients {
        /// Remove all clients before importing
        #[arg(long)]
        truncate: bool,
    },
}

impl Options {
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        let clock = Clock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match &self.subcommand {
            SC::Register { username, password } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = config.connect().await?;
                let mut txn = pool.begin().await?;
                let hasher = Argon2::default();

                let user =
                    register_user(&mut txn, &mut rng, &clock, hasher, username, password).await?;
                txn.commit().await?;
                info!(?user, "User registered");

                Ok(())
            }
            SC::Users => {
                warn!("Not implemented yet");

                Ok(())
            }
            SC::VerifyEmail { username, email } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = config.connect().await?;
                let mut txn = pool.begin().await?;

                let user = lookup_user_by_username(&mut txn, username).await?;
                let email = lookup_user_email(&mut txn, &user, email).await?;
                let email = mark_user_email_as_verified(&mut txn, &clock, email).await?;

                txn.commit().await?;
                info!(?email, "Email marked as verified");

                Ok(())
            }
            SC::ImportClients { truncate } => {
                let config: RootConfig = root.load_config()?;
                let pool = config.database.connect().await?;
                let encrypter = config.secrets.encrypter();

                let mut txn = pool.begin().await?;

                if *truncate {
                    warn!("Removing all clients first");
                    truncate_clients(&mut txn).await?;
                }

                for client in config.clients.iter() {
                    let client_id = client.client_id;
                    let res = lookup_client(&mut txn, client_id).await;
                    match res {
                        Ok(_) => {
                            warn!(%client_id, "Skipping already imported client");
                            continue;
                        }
                        Err(e) if e.not_found() => {}
                        Err(e) => anyhow::bail!(e),
                    }

                    info!(%client_id, "Importing client");
                    let client_secret = client.client_secret();
                    let client_auth_method = client.client_auth_method();
                    let jwks = client.jwks();
                    let jwks_uri = client.jwks_uri();
                    let redirect_uris = &client.redirect_uris;

                    // TODO: should be moved somewhere else
                    let encrypted_client_secret = client_secret
                        .map(|client_secret| encrypter.encryt_to_string(client_secret.as_bytes()))
                        .transpose()?;

                    insert_client_from_config(
                        &mut txn,
                        &mut rng,
                        &clock,
                        client_id,
                        client_auth_method,
                        encrypted_client_secret.as_deref(),
                        jwks,
                        jwks_uri,
                        redirect_uris,
                    )
                    .await?;
                }

                txn.commit().await?;

                Ok(())
            }
        }
    }
}
