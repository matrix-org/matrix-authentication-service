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
    DatabaseConfig, DatabaseConnectConfig, EmailConfig, EmailSmtpMode, EmailTransportConfig,
    PasswordsConfig, PolicyConfig, TemplatesConfig,
};
use mas_email::{MailTransport, Mailer};
use mas_handlers::passwords::PasswordManager;
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_templates::{TemplateLoadingError, Templates};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, PgPool,
};
use tracing::{error, info, log::LevelFilter};

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    let schemes = config
        .load()
        .await?
        .into_iter()
        .map(|(version, algorithm, secret)| {
            use mas_handlers::passwords::Hasher;
            let hasher = match algorithm {
                mas_config::PasswordAlgorithm::Pbkdf2 => Hasher::pbkdf2(secret),
                mas_config::PasswordAlgorithm::Bcrypt { cost } => Hasher::bcrypt(cost, secret),
                mas_config::PasswordAlgorithm::Argon2id => Hasher::argon2id(secret),
            };

            (version, hasher)
        });

    PasswordManager::new(schemes)
}

pub async fn mailer_from_config(
    config: &EmailConfig,
    templates: &Templates,
) -> Result<Mailer, anyhow::Error> {
    let from = config.from.parse()?;
    let reply_to = config.reply_to.parse()?;
    let transport = match &config.transport {
        EmailTransportConfig::Blackhole => MailTransport::blackhole(),
        EmailTransportConfig::Smtp {
            mode,
            hostname,
            credentials,
            port,
        } => {
            let credentials = credentials
                .clone()
                .map(|c| mas_email::SmtpCredentials::new(c.username, c.password));

            let mode = match mode {
                EmailSmtpMode::Plain => mas_email::SmtpMode::Plain,
                EmailSmtpMode::StartTls => mas_email::SmtpMode::StartTls,
                EmailSmtpMode::Tls => mas_email::SmtpMode::Tls,
            };

            MailTransport::smtp(mode, hostname, port.as_ref().copied(), credentials)
                .context("failed to build SMTP transport")?
        }
        EmailTransportConfig::Sendmail { command } => MailTransport::sendmail(command),
        EmailTransportConfig::AwsSes => MailTransport::aws_ses().await?,
    };

    Ok(Mailer::new(templates.clone(), transport, from, reply_to))
}

pub async fn policy_factory_from_config(
    config: &PolicyConfig,
) -> Result<PolicyFactory, anyhow::Error> {
    let policy_file = tokio::fs::File::open(&config.wasm_module)
        .await
        .context("failed to open OPA WASM policy file")?;

    PolicyFactory::load(
        policy_file,
        config.data.clone().unwrap_or_default(),
        config.register_entrypoint.clone(),
        config.client_registration_entrypoint.clone(),
        config.authorization_grant_entrypoint.clone(),
    )
    .await
    .context("failed to load the policy")
}

pub async fn templates_from_config(
    config: &TemplatesConfig,
    url_builder: &UrlBuilder,
) -> Result<Templates, TemplateLoadingError> {
    Templates::load(config.path.clone(), url_builder.clone()).await
}

pub async fn database_from_config(config: &DatabaseConfig) -> Result<PgPool, anyhow::Error> {
    let mut options = match &config.options {
        DatabaseConnectConfig::Uri { uri } => uri
            .parse()
            .context("could not parse database connection string")?,
        DatabaseConnectConfig::Options {
            host,
            port,
            socket,
            username,
            password,
            database,
        } => {
            let mut opts =
                PgConnectOptions::new().application_name("matrix-authentication-service");

            if let Some(host) = host {
                opts = opts.host(host);
            }

            if let Some(port) = port {
                opts = opts.port(*port);
            }

            if let Some(socket) = socket {
                opts = opts.socket(socket);
            }

            if let Some(username) = username {
                opts = opts.username(username);
            }

            if let Some(password) = password {
                opts = opts.password(password);
            }

            if let Some(database) = database {
                opts = opts.database(database);
            }

            opts
        }
    };

    options
        .log_statements(LevelFilter::Debug)
        .log_slow_statements(LevelFilter::Warn, Duration::from_millis(100));

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

/// Watch for changes in the templates folders
pub async fn watch_templates(templates: &Templates) -> anyhow::Result<()> {
    use watchman_client::{prelude::*, SubscriptionData};

    let client = Connector::new()
        .connect()
        .await
        .context("could not connect to watchman")?;

    let templates = templates.clone();

    // Find which root we're supposed to watch
    let root = templates.watch_root();

    // Create a subscription on the root
    let resolved = client
        .resolve_root(CanonicalPath::canonicalize(root)?)
        .await?;

    // Only look for *.txt, *.html and *.subject files
    let request = SubscribeRequest {
        expression: Some(Expr::Suffix(vec![
            "txt".into(),
            "html".into(),
            "subject".into(),
        ])),
        ..SubscribeRequest::default()
    };

    let (mut subscription, _) = client.subscribe::<NameOnly>(&resolved, request).await?;

    tokio::spawn(async move {
        loop {
            let event = match subscription.next().await {
                Ok(event) => event,
                Err(error) => {
                    error!(%error, "Stopped watching templates because of an error in the watchman subscription");
                    break;
                }
            };

            if let SubscriptionData::FilesChanged(QueryResult {
                files: Some(files), ..
            }) = event
            {
                let files: Vec<_> = files.into_iter().map(|f| f.name.into_inner()).collect();
                info!(?files, "Files changed, reloading templates");

                templates.clone().reload().await.unwrap_or_else(|err| {
                    error!(?err, "Error while reloading templates");
                });
            }
        }
    });

    Ok(())
}
