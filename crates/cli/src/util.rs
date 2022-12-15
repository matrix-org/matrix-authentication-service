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

use anyhow::Context;
use mas_config::{EmailConfig, EmailSmtpMode, EmailTransportConfig, PasswordsConfig, PolicyConfig};
use mas_email::{MailTransport, Mailer};
use mas_handlers::passwords::PasswordManager;
use mas_policy::PolicyFactory;
use mas_templates::Templates;

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
