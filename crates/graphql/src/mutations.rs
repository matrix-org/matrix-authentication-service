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
use async_graphql::{Context, Description, Object, ID};
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob, VerifyEmailJob},
    user::UserEmailRepository,
    RepositoryAccess,
};

use crate::{
    model::{NodeType, UserEmail},
    state::ContextExt,
};

/// The mutations root of the GraphQL interface.
#[derive(Default, Description)]
pub struct RootMutations {
    _private: (),
}

impl RootMutations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[Object(use_type_description)]
impl RootMutations {
    /// Add an email address to the specified user
    async fn add_email(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "The email address to add")] email: String,
        #[graphql(desc = "The ID of the user to add the email address to")] user_id: ID,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::User.extract_ulid(&user_id)?;
        let session = ctx.session();

        let Some(session) = session else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        if session.user.id != id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers
        // Find an existing email address
        let existing_user_email = repo.user_email().find(&session.user, &email).await?;
        let user_email = if let Some(user_email) = existing_user_email {
            user_email
        } else {
            let clock = state.clock();
            let mut rng = state.rng();

            repo.user_email()
                .add(&mut rng, &clock, &session.user, email)
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

        #[graphql(desc = "The ID of the email address to verify")] user_email_id: ID,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&user_email_id)?;
        let session = ctx.session();

        let Some(session) = session else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if user_email.user_id != session.user.id {
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

        #[graphql(desc = "The ID of the email address to verify")] user_email_id: ID,
        #[graphql(desc = "The verification code to submit")] code: String,
    ) -> Result<UserEmail, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&user_email_id)?;
        let session = ctx.session();

        let Some(session) = session else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        let clock = state.clock();
        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if user_email.user_id != session.user.id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers

        // Find the verification code
        let verification = repo
            .user_email()
            .find_verification_code(&clock, &user_email, &code)
            .await?
            .context("Invalid verification code")?;

        // TODO: display nice errors if the code was already consumed or expired
        repo.user_email()
            .consume_verification_code(&clock, verification)
            .await?;

        // XXX: is this the right place to do this?
        if session.user.primary_user_email_id.is_none() {
            repo.user_email().set_as_primary(&user_email).await?;
        }

        let user_email = repo
            .user_email()
            .mark_as_verified(&clock, user_email)
            .await?;

        repo.job()
            .schedule_job(ProvisionUserJob::new(&session.user))
            .await?;

        repo.save().await?;

        Ok(UserEmail(user_email))
    }
}
