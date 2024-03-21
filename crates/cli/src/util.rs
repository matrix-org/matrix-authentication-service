// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::time::Duration;

use anyhow::Context;
use mas_config::{
    BrandingConfig, DatabaseConfig, EmailConfig, EmailSmtpMode, EmailTransportKind,
    PasswordsConfig, PolicyConfig, TemplatesConfig,
};
use mas_email::{MailTransport, Mailer};
use mas_handlers::{passwords::PasswordManager, ActivityTracker};
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_templates::{SiteBranding, TemplateLoadingError, Templates};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, PgConnection, PgPool,
};
use tracing::{error, info, log::LevelFilter};

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    if !config.enabled() {
        return Ok(PasswordManager::disabled());
    }

    let schemes = config
        .load()
        .await?
        .into_iter()
        .map(|(version, algorithm, cost, secret)| {
            use mas_handlers::passwords::Hasher;
            let hasher = match algorithm {
                mas_config::PasswordAlgorithm::Pbkdf2 => Hasher::pbkdf2(secret),
                mas_config::PasswordAlgorithm::Bcrypt => Hasher::bcrypt(cost, secret),
                mas_config::PasswordAlgorithm::Argon2id => Hasher::argon2id(secret),
            };

            (version, hasher)
        });

    PasswordManager::new(schemes)
}

pub fn mailer_from_config(
    config: &EmailConfig,
    templates: &Templates,
) -> Result<Mailer, anyhow::Error> {
    let from = config.from.parse()?;
    let reply_to = config.reply_to.parse()?;
    let transport = match config.transport() {
        EmailTransportKind::Blackhole => MailTransport::blackhole(),
        EmailTransportKind::Smtp => {
            // This should have been set ahead of time
            let hostname = config
                .hostname()
                .context("invalid configuration: missing hostname")?;

            let mode = config
                .mode()
                .context("invalid configuration: missing mode")?;

            let credentials = match (config.username(), config.password()) {
                (Some(username), Some(password)) => Some(mas_email::SmtpCredentials::new(
                    username.to_owned(),
                    password.to_owned(),
                )),
                (None, None) => None,
                _ => {
                    anyhow::bail!("invalid configuration: missing username or password");
                }
            };

            let mode = match mode {
                EmailSmtpMode::Plain => mas_email::SmtpMode::Plain,
                EmailSmtpMode::StartTls => mas_email::SmtpMode::StartTls,
                EmailSmtpMode::Tls => mas_email::SmtpMode::Tls,
            };

            MailTransport::smtp(mode, hostname, config.port(), credentials)
                .context("failed to build SMTP transport")?
        }
        EmailTransportKind::Sendmail => MailTransport::sendmail(config.command()),
    };

    Ok(Mailer::new(templates.clone(), transport, from, reply_to))
}

pub async fn policy_factory_from_config(
    config: &PolicyConfig,
) -> Result<PolicyFactory, anyhow::Error> {
    let policy_file = tokio::fs::File::open(&config.wasm_module)
        .await
        .context("failed to open OPA WASM policy file")?;

    let entrypoints = mas_policy::Entrypoints {
        register: config.register_entrypoint.clone(),
        client_registration: config.client_registration_entrypoint.clone(),
        authorization_grant: config.authorization_grant_entrypoint.clone(),
        email: config.email_entrypoint.clone(),
        password: config.password_entrypoint.clone(),
    };

    PolicyFactory::load(
        policy_file,
        config.data.clone().unwrap_or_default(),
        entrypoints,
    )
    .await
    .context("failed to load the policy")
}

pub async fn templates_from_config(
    config: &TemplatesConfig,
    branding: &BrandingConfig,
    url_builder: &UrlBuilder,
    server_name: &str,
) -> Result<Templates, TemplateLoadingError> {
    let mut site_branding = SiteBranding::new(server_name);

    if let Some(service_name) = branding.service_name.as_deref() {
        site_branding = site_branding.with_service_name(service_name);
    }

    if let Some(policy_uri) = &branding.policy_uri {
        site_branding = site_branding.with_policy_uri(policy_uri.as_str());
    }

    if let Some(tos_uri) = &branding.tos_uri {
        site_branding = site_branding.with_tos_uri(tos_uri.as_str());
    }

    if let Some(imprint) = branding.imprint.as_deref() {
        site_branding = site_branding.with_imprint(imprint);
    }

    Templates::load(
        config.path.clone(),
        url_builder.clone(),
        config.assets_manifest.clone(),
        config.translations_path.clone(),
        site_branding,
    )
    .await
}

fn database_connect_options_from_config(
    config: &DatabaseConfig,
) -> Result<PgConnectOptions, anyhow::Error> {
    let options = if let Some(uri) = config.uri.as_deref() {
        uri.parse()
            .context("could not parse database connection string")?
    } else {
        let mut opts = PgConnectOptions::new().application_name("matrix-authentication-service");

        if let Some(host) = config.host.as_deref() {
            opts = opts.host(host);
        }

        if let Some(port) = config.port {
            opts = opts.port(port);
        }

        if let Some(socket) = config.socket.as_deref() {
            opts = opts.socket(socket);
        }

        if let Some(username) = config.username.as_deref() {
            opts = opts.username(username);
        }

        if let Some(password) = config.password.as_deref() {
            opts = opts.password(password);
        }

        if let Some(database) = config.database.as_deref() {
            opts = opts.database(database);
        }

        opts
    };

    let options = options
        .log_statements(LevelFilter::Debug)
        .log_slow_statements(LevelFilter::Warn, Duration::from_millis(100));

    Ok(options)
}

/// Create a database connection pool from the configuration
#[tracing::instrument(name = "db.connect", skip_all, err(Debug))]
pub async fn database_pool_from_config(config: &DatabaseConfig) -> Result<PgPool, anyhow::Error> {
    let options = database_connect_options_from_config(config)?;
    PgPoolOptions::new()
        .max_connections(config.max_connections.into())
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime)
        .connect_with(options)
        .await
        .context("could not connect to the database")
}

/// Create a single database connection from the configuration
#[tracing::instrument(name = "db.connect", skip_all, err(Debug))]
pub async fn database_connection_from_config(
    config: &DatabaseConfig,
) -> Result<PgConnection, anyhow::Error> {
    database_connect_options_from_config(config)?
        .connect()
        .await
        .context("could not connect to the database")
}

/// Reload templates on SIGHUP
pub fn register_sighup(
    templates: &Templates,
    activity_tracker: &ActivityTracker,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let templates = templates.clone();
        let activity_tracker = activity_tracker.clone();

        tokio::spawn(async move {
            loop {
                if signal.recv().await.is_none() {
                    // No more signals will be received, breaking
                    break;
                };

                info!("SIGHUP received, reloading templates & flushing activity tracker");

                activity_tracker.flush().await;
                templates.clone().reload().await.unwrap_or_else(|err| {
                    error!(?err, "Error while reloading templates");
                });
            }
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use zeroize::Zeroizing;

    use super::*;

    #[tokio::test]
    async fn test_password_manager_from_config() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new(b"hunter2".to_vec());

        // Test a valid, enabled config
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 10,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(manager.is_enabled());
        let hashed = manager.hash(&mut rng, password.clone()).await;
        assert!(hashed.is_ok());
        let (version, hashed) = hashed.unwrap();
        assert_eq!(version, 42);
        assert!(hashed.starts_with("$argon2id$"));

        // Test a valid, disabled config
        let config = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "schemes": []
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(!manager.is_enabled());
        let res = manager.hash(&mut rng, password.clone()).await;
        assert!(res.is_err());

        // Test an invalid config
        // Repeat the same version twice
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 42,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());

        // Empty schemes
        let config = serde_json::from_value(serde_json::json!({
            "schemes": []
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());
    }
}
