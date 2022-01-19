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

use std::sync::Arc;

use async_trait::async_trait;
use lettre::{
    address::Envelope,
    message::{Mailbox, MessageBuilder, MultiPart},
    transport::smtp::{authentication::Credentials, AsyncSmtpTransport},
    AsyncTransport, Message, Tokio1Executor,
};
use mas_config::{EmailSmtpMode, EmailTransportConfig};
use mas_templates::{EmailVerificationContext, Templates};

#[derive(Default, Clone)]
pub struct MailTransport {
    inner: Arc<MailTransportInner>,
}

enum MailTransportInner {
    Blackhole,
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
}

impl TryFrom<&EmailTransportConfig> for MailTransport {
    type Error = anyhow::Error;

    fn try_from(config: &EmailTransportConfig) -> Result<Self, Self::Error> {
        let inner = match config {
            EmailTransportConfig::Blackhole => MailTransportInner::Blackhole,
            EmailTransportConfig::Smtp {
                mode,
                hostname,
                credentials,
                port,
            } => {
                let mut t = match mode {
                    EmailSmtpMode::Plain => {
                        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(hostname)
                    }
                    EmailSmtpMode::StartTls => {
                        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(hostname)?
                    }
                    EmailSmtpMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(hostname)?,
                };

                if let Some(credentials) = credentials {
                    t = t.credentials(Credentials::new(
                        credentials.username.clone(),
                        credentials.password.clone(),
                    ));
                }

                if let Some(port) = port {
                    t = t.port(*port);
                }

                MailTransportInner::Smtp(t.build())
            }
        };
        let inner = Arc::new(inner);
        Ok(Self { inner })
    }
}

impl MailTransport {
    pub async fn test_connection(&self) -> anyhow::Result<()> {
        match self.inner.as_ref() {
            MailTransportInner::Blackhole => {}
            MailTransportInner::Smtp(t) => {
                t.test_connection().await?;
            }
        }

        Ok(())
    }
}

impl Default for MailTransportInner {
    fn default() -> Self {
        Self::Blackhole
    }
}

#[async_trait]
impl AsyncTransport for MailTransport {
    type Ok = ();
    type Error = anyhow::Error;

    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        match self.inner.as_ref() {
            MailTransportInner::Blackhole => {
                tracing::warn!(
                    ?envelope,
                    "An email was supposed to be sent but no email backend is configured"
                );
            }
            MailTransportInner::Smtp(t) => {
                t.send_raw(envelope, email).await?;
            }
        };

        Ok(())
    }
}

#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

impl Mailer {
    pub fn new(
        templates: &Templates,
        transport: &MailTransport,
        from: &Mailbox,
        reply_to: &Mailbox,
    ) -> Self {
        Self {
            templates: templates.clone(),
            transport: transport.clone(),
            from: from.clone(),
            reply_to: reply_to.clone(),
        }
    }

    fn base_message(&self) -> MessageBuilder {
        Message::builder()
            .from(self.from.clone())
            .reply_to(self.reply_to.clone())
    }

    async fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &EmailVerificationContext,
    ) -> anyhow::Result<Message> {
        let plain = self
            .templates
            .render_email_verification_txt(context)
            .await?;

        let html = self
            .templates
            .render_email_verification_html(context)
            .await?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let message = self
            .base_message()
            // TODO: template/localize this
            .subject("Verify your email address")
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &EmailVerificationContext,
    ) -> anyhow::Result<()> {
        let message = self.prepare_verification_email(to, context).await?;
        self.transport.send(message).await?;
        Ok(())
    }
}
