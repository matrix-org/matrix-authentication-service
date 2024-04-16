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

use std::{collections::HashMap, io::Write};

use anyhow::Context;
use clap::{ArgAction, CommandFactory, Parser};
use figment::Figment;
use mas_config::{ConfigurationSection, DatabaseConfig, PasswordsConfig};
use mas_data_model::{Device, TokenType, Ulid, UpstreamOAuthProvider, User};
use mas_email::Address;
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    job::{DeactivateUserJob, DeleteDeviceJob, JobRepositoryExt, ProvisionUserJob},
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
    Clock, RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::{RngCore, SeedableRng};
use sqlx::{types::Uuid, Acquire};
use tracing::{info, info_span, warn};

use crate::util::{database_connection_from_config, password_manager_from_config};

const USER_ATTRIBUTES_HEADING: &str = "User attributes";

#[derive(Debug, Clone)]
struct UpstreamProviderMapping {
    upstream_provider_id: Ulid,
    subject: String,
}

fn parse_upstream_provider_mapping(s: &str) -> Result<UpstreamProviderMapping, anyhow::Error> {
    let (id, subject) = s.split_once(':').context("Invalid format")?;
    let upstream_provider_id = id.parse().context("Invalid upstream provider ID")?;
    let subject = subject.to_owned();

    Ok(UpstreamProviderMapping {
        upstream_provider_id,
        subject,
    })
}

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

    /// Register a user
    RegisterUser {
        /// Username to register
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        username: Option<String>,

        /// Password to set
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        password: Option<String>,

        /// Email to add
        #[arg(short, long = "email", action = ArgAction::Append, help_heading = USER_ATTRIBUTES_HEADING)]
        emails: Vec<Address>,

        /// Upstream OAuth 2.0 provider mapping to add
        #[arg(
            short = 'M',
            long = "upstream-provider-mapping",
            value_parser = parse_upstream_provider_mapping,
            action = ArgAction::Append,
            value_name = "UPSTREAM_PROVIDER_ID:SUBJECT",
            help_heading = USER_ATTRIBUTES_HEADING
        )]
        upstream_provider_mappings: Vec<UpstreamProviderMapping>,

        /// Make the user an admin
        #[arg(long, action = ArgAction::SetTrue, help_heading = USER_ATTRIBUTES_HEADING)]
        admin: bool,

        /// Set the user's display name
        #[arg(short = 'D', long, help_heading = USER_ATTRIBUTES_HEADING)]
        display_name: Option<String>,
    },
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<()> {
        use Subcommand as SC;
        let clock = SystemClock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match self.subcommand {
            SC::SetPassword { username, password } => {
                let _span =
                    info_span!("cli.manage.set_password", user.username = %username).entered();

                let database_config = DatabaseConfig::extract(figment)?;
                let passwords_config = PasswordsConfig::extract(figment)?;

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

                let database_config = DatabaseConfig::extract(figment)?;
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
                let database_config = DatabaseConfig::extract(figment)?;
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
                let database_config = DatabaseConfig::extract(figment)?;
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
                let database_config = DatabaseConfig::extract(figment)?;
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
                let config = DatabaseConfig::extract(figment)?;
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
                let config = DatabaseConfig::extract(figment)?;
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

            SC::RegisterUser {
                username,
                password,
                emails,
                upstream_provider_mappings,
                admin,
                display_name,
            } => {
                let password_config = PasswordsConfig::extract(figment)?;
                let database_config = DatabaseConfig::extract(figment)?;

                let password_manager = password_manager_from_config(&password_config).await?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                // Load all the providers we need
                let mut upstream_providers = HashMap::new();
                for mapping in &upstream_provider_mappings {
                    if upstream_providers.contains_key(&mapping.upstream_provider_id) {
                        continue;
                    }

                    let provider = repo
                        .upstream_oauth_provider()
                        .lookup(mapping.upstream_provider_id)
                        .await?
                        .context("Upstream provider not found")?;

                    upstream_providers.insert(provider.id, provider);
                }

                let upstream_provider_mappings = upstream_provider_mappings
                    .into_iter()
                    .map(|mapping| {
                        (
                            &upstream_providers[&mapping.upstream_provider_id],
                            mapping.subject,
                        )
                    })
                    .collect();

                // Hash the password if it's provided
                let hashed_password = if let Some(password) = password {
                    let password = password.into_bytes().into();
                    Some(password_manager.hash(&mut rng, password).await?)
                } else {
                    None
                };

                // TODO: prompt
                let username = username.context("Username is required")?;

                if repo.user().exists(&username).await? {
                    anyhow::bail!("User already exists");
                }

                let req = UserCreationRequest {
                    username,
                    hashed_password,
                    emails,
                    upstream_provider_mappings,
                    display_name,
                    admin,
                };

                req.command(&mut std::io::stdout())?;

                //do_register(&mut repo, &mut rng, &clock, req).await?;

                repo.into_inner().commit().await?;

                Ok(())
            }
        }
    }
}

struct UserCreationRequest<'a> {
    username: String,
    hashed_password: Option<(u16, String)>,
    emails: Vec<Address>,
    upstream_provider_mappings: Vec<(&'a UpstreamOAuthProvider, String)>,
    display_name: Option<String>,
    admin: bool,
}

impl<'a> UserCreationRequest<'a> {
    fn command<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        let command = super::Options::command();
        let manage = command.find_subcommand("manage").unwrap();
        let register_user = manage.find_subcommand("register-user").unwrap();
        let username_arg = &register_user[&clap::Id::from("username")];
        let password_arg = &register_user[&clap::Id::from("password")];
        let email_arg = &register_user[&clap::Id::from("emails")];
        let upstream_provider_mapping_arg =
            &register_user[&clap::Id::from("upstream_provider_mappings")];
        let display_name_arg = &register_user[&clap::Id::from("display_name")];
        let admin_arg = &register_user[&clap::Id::from("admin")];

        write!(
            w,
            "{} {} {}",
            command.get_name(),
            manage.get_name(),
            register_user.get_name()
        )?;

        write!(
            w,
            " --{} {:?}",
            username_arg.get_long().unwrap(),
            self.username
        )?;

        for email in &self.emails {
            let email: &str = email.as_ref();
            write!(w, " --{} {email:?}", email_arg.get_long().unwrap())?;
        }

        if let Some(display_name) = &self.display_name {
            write!(
                w,
                " --{} {:?}",
                display_name_arg.get_long().unwrap(),
                display_name
            )?;
        }

        if self.hashed_password.is_some() {
            write!(w, " --{} $PASSWORD", password_arg.get_long().unwrap())?;
        }

        for (provider, subject) in &self.upstream_provider_mappings {
            let mapping = format!("{}:{}", provider.id, subject);
            write!(
                w,
                " --{} {mapping:?}",
                upstream_provider_mapping_arg.get_long().unwrap(),
            )?;
        }

        if self.admin {
            write!(w, " --{}", admin_arg.get_long().unwrap())?;
        }

        Ok(())
    }
}

async fn do_register<'a, E: std::error::Error + Send + Sync + 'static>(
    repo: &mut dyn RepositoryAccess<Error = E>,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    UserCreationRequest {
        username,
        hashed_password,
        emails,
        upstream_provider_mappings,
        display_name,
        admin,
    }: UserCreationRequest<'a>,
) -> Result<User, E> {
    let mut user = repo.user().add(rng, clock, username).await?;

    if let Some((version, hashed_password)) = hashed_password {
        repo.user_password()
            .add(rng, clock, &user, version, hashed_password, None)
            .await?;
    }

    for email in emails {
        let user_email = repo
            .user_email()
            .add(rng, clock, &user, email.to_string())
            .await?;

        let user_email = repo
            .user_email()
            .mark_as_verified(clock, user_email)
            .await?;

        if user.primary_user_email_id.is_none() {
            repo.user_email().set_as_primary(&user_email).await?;
            user.primary_user_email_id = Some(user_email.id);
        }
    }

    for (provider, subject) in upstream_provider_mappings {
        let link = repo
            .upstream_oauth_link()
            .add(rng, clock, provider, subject)
            .await?;

        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await?;
    }

    if admin {
        user = repo.user().set_can_request_admin(user, true).await?;
    }

    let mut provision_job = ProvisionUserJob::new(&user);
    if let Some(display_name) = display_name {
        provision_job = provision_job.set_display_name(display_name);
    }

    repo.job().schedule_job(provision_job).await?;

    Ok(user)
}
