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

use anyhow::Context as _;
use async_graphql::{Context, InputObject, Object, ID};
use mas_storage::job::{JobRepositoryExt, ProvisionUserJob, VerifyEmailJob};

use crate::{
    model::{NodeType, UserEmail},
    state::ContextExt,
};

#[derive(Default)]
pub struct UserEmailMutations {
    _private: (),
}

/// The input for the `addEmail` mutation
#[derive(InputObject)]
struct AddEmailInput {
    /// The email address to add
    email: String,
    /// The ID of the user to add the email address to
    user_id: ID,
}

/// The input for the `sendVerificationEmail` mutation
#[derive(InputObject)]
struct SendVerificationEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
}

/// The input for the `verifyEmail` mutation
#[derive(InputObject)]
struct VerifyEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
    /// The verification code
    code: String,
}

#[Object]
impl UserEmailMutations {
    /// Add an email address to the specified user
    async fn add_email(
        &self,
        ctx: &Context<'_>,
        input: AddEmailInput,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        let user = requester.user().context("Unauthorized")?;

        if user.id != id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers
        // Find an existing email address
        let existing_user_email = repo.user_email().find(user, &input.email).await?;
        let user_email = if let Some(user_email) = existing_user_email {
            user_email
        } else {
            let clock = state.clock();
            let mut rng = state.rng();

            repo.user_email()
                .add(&mut rng, &clock, user, input.email)
                .await?
        };

        // Schedule a job to verify the email address if needed
        if user_email.confirmed_at.is_none() {
            repo.job()
                .schedule_job(VerifyEmailJob::new(&user_email))
                .await?;
        }

        repo.save().await?;

        Ok(UserEmail(user_email))
    }

    /// Send a verification code for an email address
    async fn send_verification_email(
        &self,
        ctx: &Context<'_>,
        input: SendVerificationEmailInput,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();
        let user = requester.user().context("Unauthorized")?;

        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if user_email.user_id != user.id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // Schedule a job to verify the email address if needed
        if user_email.confirmed_at.is_none() {
            repo.job()
                .schedule_job(VerifyEmailJob::new(&user_email))
                .await?;
        }

        repo.save().await?;

        Ok(UserEmail(user_email))
    }

    /// Submit a verification code for an email address
    async fn verify_email(
        &self,
        ctx: &Context<'_>,
        input: VerifyEmailInput,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();

        let user = requester.user().context("Unauthorized")?;

        let clock = state.clock();
        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if user_email.user_id != user.id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        if user_email.confirmed_at.is_some() {
            // Just return the email address if it's already verified
            // XXX: should we return an error instead?
            return Ok(UserEmail(user_email));
        }

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers

        // Find the verification code
        let verification = repo
            .user_email()
            .find_verification_code(&clock, &user_email, &input.code)
            .await?
            .context("Invalid verification code")?;

        if verification.is_valid() {
            return Err(async_graphql::Error::new("Invalid verification code"));
        }

        // TODO: display nice errors if the code was already consumed or expired
        repo.user_email()
            .consume_verification_code(&clock, verification)
            .await?;

        // XXX: is this the right place to do this?
        if user.primary_user_email_id.is_none() {
            repo.user_email().set_as_primary(&user_email).await?;
        }

        let user_email = repo
            .user_email()
            .mark_as_verified(&clock, user_email)
            .await?;

        repo.job().schedule_job(ProvisionUserJob::new(user)).await?;

        repo.save().await?;

        Ok(UserEmail(user_email))
    }
}
