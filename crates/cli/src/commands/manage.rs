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
    job::{DeactivateUserJob, DeleteDeviceJob, JobRepositoryExt, ProvisionUserJob},
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
    RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use sqlx::{types::Uuid, Acquire};
use tracing::{info, info_span, warn};

use crate::util::{database_connection_from_config, password_manager_from_config};

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

    /// Trigger a provisioning job for all users
    ProvisionAllUsers,

    /// Kill all sessions for a user
    KillSessions {
        /// User for which to kill sessions
        username: String,

        /// Do a dry run
        #[arg(long)]
        dry_run: bool,
    },

    /// Lock a user
    LockUser {
        /// User to lock
        username: String,

        /// Whether to deactivate the user
        #[arg(long)]
        deactivate: bool,
    },

    /// Unlock a user
    UnlockUser {
        /// User to unlock
        username: String,
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

                let mut conn = database_connection_from_config(&database_config).await?;
                let password_manager = password_manager_from_config(&passwords_config).await?;

                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);
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
                repo.into_inner().commit().await?;

                Ok(())
            }

            SC::VerifyEmail { username, email } => {
                let _span = info_span!(
                    "cli.manage.verify_email",
                    user.username = username,
                    user_email.email = email
                )
                .entered();

                let database_config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

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

                // If the user has no primary email, set this one as primary.
                if user.primary_user_email_id.is_none() {
                    repo.user_email().set_as_primary(&email).await?;
                }

                repo.into_inner().commit().await?;
                info!(?email, "Email marked as verified");

                Ok(())
            }

            SC::IssueCompatibilityToken {
                username,
                admin,
                device_id,
            } => {
                let database_config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

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
                    .add(&mut rng, &clock, &user, device, None, admin)
                    .await?;

                let token = TokenType::CompatAccessToken.generate(&mut rng);

                let compat_access_token = repo
                    .compat_access_token()
                    .add(&mut rng, &clock, &compat_session, token, None)
                    .await?;

                repo.into_inner().commit().await?;

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

            SC::ProvisionAllUsers => {
                let _span = info_span!("cli.manage.provision_all_users").entered();
                let database_config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let mut txn = conn.begin().await?;

                // TODO: do some pagination here
                let ids: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM users")
                    .fetch_all(&mut *txn)
                    .await?;

                let mut repo = PgRepository::from_conn(txn);

                for id in ids {
                    let id = id.into();
                    info!(user.id = %id, "Scheduling provisioning job");
                    let job = ProvisionUserJob::new_for_id(id);
                    repo.job().schedule_job(job).await?;
                }

                repo.into_inner().commit().await?;

                Ok(())
            }

            SC::KillSessions { username, dry_run } => {
                let _span =
                    info_span!("cli.manage.kill_sessions", user.username = username).entered();
                let database_config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let compat_sessions_ids: Vec<Uuid> = sqlx::query_scalar(
                    r"
                        SELECT compat_session_id FROM compat_sessions
                        WHERE user_id = $1 AND finished_at IS NULL
                    ",
                )
                .bind(Uuid::from(user.id))
                .fetch_all(&mut **repo)
                .await?;

                for id in compat_sessions_ids {
                    let id = id.into();
                    let compat_session = repo
                        .compat_session()
                        .lookup(id)
                        .await?
                        .context("Session not found")?;
                    info!(%compat_session.id, %compat_session.device, "Killing compat session");

                    if dry_run {
                        continue;
                    }

                    let job = DeleteDeviceJob::new(&user, &compat_session.device);
                    repo.job().schedule_job(job).await?;
                    repo.compat_session().finish(&clock, compat_session).await?;
                }

                let oauth2_sessions_ids: Vec<Uuid> = sqlx::query_scalar(
                    r"
                        SELECT oauth2_sessions.oauth2_session_id 
                        FROM oauth2_sessions
                        INNER JOIN user_sessions USING (user_session_id)
                        WHERE user_sessions.user_id = $1 AND oauth2_sessions.finished_at IS NULL
                    ",
                )
                .bind(Uuid::from(user.id))
                .fetch_all(&mut **repo)
                .await?;

                for id in oauth2_sessions_ids {
                    let id = id.into();
                    let oauth2_session = repo
                        .oauth2_session()
                        .lookup(id)
                        .await?
                        .context("Session not found")?;
                    info!(%oauth2_session.id, %oauth2_session.scope, "Killing oauth2 session");

                    if dry_run {
                        continue;
                    }

                    for scope in &*oauth2_session.scope {
                        if let Some(device) = Device::from_scope_token(scope) {
                            // Schedule a job to delete the device.
                            repo.job()
                                .schedule_job(DeleteDeviceJob::new(&user, &device))
                                .await?;
                        }
                    }

                    repo.oauth2_session().finish(&clock, oauth2_session).await?;
                }

                let user_sessions_ids: Vec<Uuid> = sqlx::query_scalar(
                    r"
                        SELECT user_session_id FROM user_sessions
                        WHERE user_id = $1 AND finished_at IS NULL
                    ",
                )
                .bind(Uuid::from(user.id))
                .fetch_all(&mut **repo)
                .await?;

                for id in user_sessions_ids {
                    let id = id.into();
                    let browser_session = repo
                        .browser_session()
                        .lookup(id)
                        .await?
                        .context("Session not found")?;
                    info!(%browser_session.id, "Killing browser session");

                    if dry_run {
                        continue;
                    }

                    repo.browser_session()
                        .finish(&clock, browser_session)
                        .await?;
                }

                let txn = repo.into_inner();
                if dry_run {
                    info!("Dry run, not saving");
                    txn.rollback().await?;
                } else {
                    txn.commit().await?;
                }

                Ok(())
            }

            SC::LockUser {
                username,
                deactivate,
            } => {
                let _span = info_span!("cli.manage.lock_user", user.username = username).entered();
                let config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                info!(%user.id, "Locking user");

                // Even though the deactivation job will lock the user, we lock it here in case
                // the worker is not running, as we don't have a good way to run a job
                // synchronously yet.
                let user = repo.user().lock(&clock, user).await?;

                if deactivate {
                    warn!(%user.id, "Scheduling user deactivation");
                    repo.job()
                        .schedule_job(DeactivateUserJob::new(&user, false))
                        .await?;
                }

                repo.into_inner().commit().await?;

                Ok(())
            }

            SC::UnlockUser { username } => {
                let _span = info_span!("cli.manage.lock_user", user.username = username).entered();
                let config: DatabaseConfig = root.load_config()?;
                let mut conn = database_connection_from_config(&config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                info!(%user.id, "Unlocking user");

                repo.user().unlock(user).await?;
                repo.into_inner().commit().await?;

                Ok(())
            }
        }
    }
}
