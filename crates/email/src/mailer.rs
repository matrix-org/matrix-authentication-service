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
use mas_templates::{EmailVerificationContext, Templates, WithLanguage};
use thiserror::Error;

use crate::MailTransport;

/// Helps sending mails to users
#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

/// Errors that can occur when sending emails
#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    /// Mail failed to send through the transport
    Transport(#[from] crate::transport::Error),

    /// Failed to render email templates
    Templates(#[from] mas_templates::TemplateError),

    /// Email built was invalid
    Content(#[from] lettre::error::Error),
}

impl Mailer {
    /// Constructs a new [`Mailer`]
    #[must_use]
    pub fn new(
        templates: Templates,
        transport: MailTransport,
        from: Mailbox,
        reply_to: Mailbox,
    ) -> Self {
        Self {
            templates,
            transport,
            from,
            reply_to,
        }
    }

    fn base_message(&self) -> MessageBuilder {
        Message::builder()
            .from(self.from.clone())
            .reply_to(self.reply_to.clone())
    }

    fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<Message, Error> {
        let plain = self.templates.render_email_verification_txt(context)?;

        let html = self.templates.render_email_verification_html(context)?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let subject = self.templates.render_email_verification_subject(context)?;

        let message = self
            .base_message()
            .subject(subject.trim())
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    /// Send the verification email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
    #[tracing::instrument(
        name = "email.verification.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
            user.id = %context.user().id,
            user_email_verification.id = %context.verification().id,
            user_email_verification.code = context.verification().code,
        ),
        err,
    )]
    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<(), Error> {
        let message = self.prepare_verification_email(to, context)?;
        self.transport.send(message).await?;
        Ok(())
    }

    /// Test the connetion to the mail server
    ///
    /// # Errors
    ///
    /// Returns an error if the connection failed
    #[tracing::instrument(name = "email.test_connection", skip_all, err)]
    pub async fn test_connection(&self) -> Result<(), crate::transport::Error> {
        self.transport.test_connection().await
    }
}
