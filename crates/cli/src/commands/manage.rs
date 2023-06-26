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

use anyhow::Context;
use clap::Parser;
use mas_config::{DatabaseConfig, PasswordsConfig};
use mas_data_model::{Device, TokenType};
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
    Repository, RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use tracing::{info, info_span};

use crate::util::{database_from_config, password_manager_from_config};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Mark email address as verified
    VerifyEmail { username: String, email: String },

    /// Set a user password
    SetPassword { username: String, password: String },

    /// Issue a compatibility token
    IssueCompatibilityToken {
        /// User for which to issue the token
        username: String,

        /// Device ID to set in the token. If not specified, a random device ID
        /// will be generated.
        device_id: Option<String>,

        /// Whether that token should be admin
        #[arg(long = "yes-i-want-to-grant-synapse-admin-privileges")]
        admin: bool,
    },
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        let clock = SystemClock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match self.subcommand {
            SC::SetPassword { username, password } => {
                let _span =
                    info_span!("cli.manage.set_password", user.username = %username).entered();

                let database_config: DatabaseConfig = root.load_config()?;
                let passwords_config: PasswordsConfig = root.load_config()?;

                let pool = database_from_config(&database_config).await?;
                let password_manager = password_manager_from_config(&passwords_config).await?;

                let mut repo = PgRepository::from_pool(&pool).await?.boxed();
                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let password = password.into_bytes().into();

                let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;

                repo.user_password()
                    .add(&mut rng, &clock, &user, version, hashed_password, None)
                    .await?;

                info!(%user.id, %user.username, "Password changed");
                repo.save().await?;

                Ok(())
            }

            SC::VerifyEmail { username, email } => {
                let _span = info_span!(
                    "cli.manage.verify_email",
                    user.username = username,
                    user_email.email = email
                )
                .entered();

                let config: DatabaseConfig = root.load_config()?;
                let pool = database_from_config(&config).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let email = repo
                    .user_email()
                    .find(&user, &email)
                    .await?
                    .context("Email not found")?;
                let email = repo.user_email().mark_as_verified(&clock, email).await?;

                repo.save().await?;
                info!(?email, "Email marked as verified");

                Ok(())
            }

            SC::IssueCompatibilityToken {
                username,
                admin,
                device_id,
            } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = database_from_config(&config).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let device = if let Some(device_id) = device_id {
                    device_id.try_into()?
                } else {
                    Device::generate(&mut rng)
                };

                let compat_session = repo
                    .compat_session()
                    .add(&mut rng, &clock, &user, device, admin)
                    .await?;

                let token = TokenType::CompatAccessToken.generate(&mut rng);

                let compat_access_token = repo
                    .compat_access_token()
                    .add(&mut rng, &clock, &compat_session, token, None)
                    .await?;

                repo.save().await?;

                info!(
                    %compat_access_token.id,
                    %compat_session.id,
                    %compat_session.device,
                    %user.id,
                    %user.username,
                    "Compatibility token issued: {}", compat_access_token.token
                );

                Ok(())
            }
        }
    }
}
