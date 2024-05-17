// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use apalis::prelude::{Monitor, TokioExecutor};
use apalis_core::layers::extensions::Data;
use chrono::Duration;
use mas_email::{Address, Mailbox};
use mas_i18n::locale;
use mas_storage::job::{JobWithSpanContext, VerifyEmailJob};
use mas_templates::{EmailVerificationContext, TemplateContext};
use rand::{distributions::Uniform, Rng};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

use crate::State;

#[derive(Debug, Error)]
pub enum Error {
    #[error("User email not found: {0}")]
    UserEmailNotFound(Ulid),

    #[error("User not found: {0}")]
    UserNotFound(Ulid),

    #[error("Repository error")]
    Repositoru(#[from] mas_storage::RepositoryError),

    #[error("Invalid email address")]
    InvalidEmailAddress(#[from] mas_email::AddressError),

    #[error("Failed to send email")]
    Mailer(#[from] mas_email::MailerError),
}

#[tracing::instrument(
    name = "job.verify_email",
    fields(user_email.id = %job.user_email_id()),
    skip_all,
    err,
)]
async fn verify_email(
    job: JobWithSpanContext<VerifyEmailJob>,
    state: Data<State>,
) -> Result<(), Error> {
    let mut repo = state.repository().await?;
    let mut rng = state.rng();
    let mailer = state.mailer();
    let clock = state.clock();

    let language = job
        .language()
        .and_then(|l| l.parse().ok())
        .unwrap_or(locale!("en").into());

    // Lookup the user email
    let user_email = repo
        .user_email()
        .lookup(job.user_email_id())
        .await?
        .ok_or(Error::UserEmailNotFound(job.user_email_id()))?;

    // Lookup the user associated with the email
    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .ok_or(Error::UserNotFound(user_email.user_id))?;

    // Generate a verification code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");

    let address: Address = user_email.email.parse()?;

    // Save the verification code in the database
    let verification = repo
        .user_email()
        .add_verification_code(
            &mut rng,
            &clock,
            &user_email,
            Duration::try_hours(8).unwrap(),
            code,
        )
        .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context =
        EmailVerificationContext::new(user.clone(), verification.clone()).with_language(language);

    mailer.send_verification_email(mailbox, &context).await?;

    info!(
        email.id = %user_email.id,
        "Verification email sent"
    );

    repo.save().await?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    pool: &PgPool,
) -> Monitor<TokioExecutor> {
    let verify_email_worker = crate::build!(VerifyEmailJob => verify_email, suffix, state, pool);

    monitor.register(verify_email_worker)
}
