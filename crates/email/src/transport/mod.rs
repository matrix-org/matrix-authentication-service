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

//! Email transport backends

use std::sync::Arc;

use async_trait::async_trait;
use lettre::{
    address::Envelope,
    transport::{
        sendmail::AsyncSendmailTransport,
        smtp::{authentication::Credentials, AsyncSmtpTransport},
    },
    AsyncTransport, Tokio1Executor,
};
use mas_config::{EmailSmtpMode, EmailTransportConfig};

pub mod aws_ses;

/// A wrapper around many [`AsyncTransport`]s
#[derive(Default, Clone)]
pub struct Transport {
    inner: Arc<TransportInner>,
}

enum TransportInner {
    Blackhole,
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    Sendmail(AsyncSendmailTransport<Tokio1Executor>),
    AwsSes(aws_ses::Transport),
}

impl Transport {
    /// Construct a transport from a user configration
    ///
    /// # Errors
    ///
    /// Will return `Err` on invalid confiuration
    pub async fn from_config(config: &EmailTransportConfig) -> Result<Self, anyhow::Error> {
        let inner = match config {
            EmailTransportConfig::Blackhole => TransportInner::Blackhole,
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
                    t = t.port((*port).into());
                }

                TransportInner::Smtp(t.build())
            }
            EmailTransportConfig::Sendmail { command } => {
                TransportInner::Sendmail(AsyncSendmailTransport::new_with_command(command))
            }
            EmailTransportConfig::AwsSes => {
                TransportInner::AwsSes(aws_ses::Transport::from_env().await)
            }
        };
        let inner = Arc::new(inner);
        Ok(Self { inner })
    }
}

impl Transport {
    /// Test the connection to the underlying transport. Only works with the
    /// SMTP backend for now
    ///
    /// # Errors
    ///
    /// Will return `Err` if the connection test failed
    pub async fn test_connection(&self) -> anyhow::Result<()> {
        match self.inner.as_ref() {
            TransportInner::Smtp(t) => {
                t.test_connection().await?;
            }
            TransportInner::Blackhole | TransportInner::Sendmail(_) | TransportInner::AwsSes(_) => {
            }
        }

        Ok(())
    }
}

impl Default for TransportInner {
    fn default() -> Self {
        Self::Blackhole
    }
}

#[async_trait]
impl AsyncTransport for Transport {
    type Ok = ();
    type Error = anyhow::Error;

    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        match self.inner.as_ref() {
            TransportInner::Blackhole => {
                tracing::warn!(
                    ?envelope,
                    "An email was supposed to be sent but no email backend is configured"
                );
            }
            TransportInner::Smtp(t) => {
                t.send_raw(envelope, email).await?;
            }
            TransportInner::Sendmail(t) => {
                t.send_raw(envelope, email).await?;
            }
            TransportInner::AwsSes(t) => {
                t.send_raw(envelope, email).await?;
            }
        };

        Ok(())
    }
}
