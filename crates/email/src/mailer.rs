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

//! Send emails to users

use lettre::{
    message::{Mailbox, MessageBuilder, MultiPart},
    AsyncTransport, Message,
};
use mas_templates::{EmailVerificationContext, Templates};

use crate::MailTransport;

/// Helps sending mails to users
#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

impl Mailer {
    /// Constructs a new [`Mailer`]
    #[must_use]
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

    /// Send the verification email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
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
