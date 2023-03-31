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

use anyhow::Context;
use apalis_core::{
    builder::{WorkerBuilder, WorkerFactory},
    context::JobContext,
    executor::TokioExecutor,
    job_fn::job_fn,
    monitor::Monitor,
    storage::builder::WithStorage,
};
use chrono::Duration;
use mas_email::{Address, EmailVerificationContext, Mailbox};
use mas_storage::job::VerifyEmailJob;
use rand::{distributions::Uniform, Rng};
use tracing::info;

use crate::{JobContextExt, State};

async fn verify_email(job: VerifyEmailJob, ctx: JobContext) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let mut repo = state.repository().await?;
    let mut rng = state.rng();
    let mailer = state.mailer();
    let clock = state.clock();

    // Lookup the user email
    let user_email = repo
        .user_email()
        .lookup(job.user_email_id())
        .await?
        .context("User email not found")?;

    // Lookup the user associated with the email
    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("User not found")?;

    // Generate a verification code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");

    let address: Address = user_email.email.parse()?;

    // Save the verification code in the database
    let verification = repo
        .user_email()
        .add_verification_code(&mut rng, &clock, &user_email, Duration::hours(8), code)
        .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context = EmailVerificationContext::new(user.clone(), verification.clone());

    mailer.send_verification_email(mailbox, &context).await?;

    info!(
        email.id = %user_email.id,
        "Verification email sent"
    );

    repo.save().await?;

    Ok(())
}

pub(crate) fn register(monitor: Monitor<TokioExecutor>, state: &State) -> Monitor<TokioExecutor> {
    let storage = state.store();
    let worker = WorkerBuilder::new("verify-email")
        .layer(state.inject())
        .with_storage(storage)
        .build(job_fn(verify_email));
    monitor.register(worker)
}
