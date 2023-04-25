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
use async_graphql::{Context, Description, Enum, InputObject, Object, ID};
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob, VerifyEmailJob},
    user::UserRepository,
    RepositoryAccess,
};

use crate::{
    model::{NodeType, User, UserEmail},
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

/// The status of the `addEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum AddEmailStatus {
    /// The email address was added
    Added,
    /// The email address already exists
    Exists,
}

/// The payload of the `addEmail` mutation
#[derive(Description)]
enum AddEmailPayload {
    Added(mas_data_model::UserEmail),
    Exists(mas_data_model::UserEmail),
}

#[Object(use_type_description)]
impl AddEmailPayload {
    /// Status of the operation
    async fn status(&self) -> AddEmailStatus {
        match self {
            AddEmailPayload::Added(_) => AddEmailStatus::Added,
            AddEmailPayload::Exists(_) => AddEmailStatus::Exists,
        }
    }

    /// The email address that was added
    async fn email(&self) -> UserEmail {
        match self {
            AddEmailPayload::Added(email) | AddEmailPayload::Exists(email) => {
                UserEmail(email.clone())
            }
        }
    }

    /// The user to whom the email address was added
    async fn user(&self, ctx: &Context<'_>) -> Result<User, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            AddEmailPayload::Added(email) | AddEmailPayload::Exists(email) => email.user_id,
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(User(user))
    }
}

/// The input for the `sendVerificationEmail` mutation
#[derive(InputObject)]
struct SendVerificationEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
}

/// The status of the `sendVerificationEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SendVerificationEmailStatus {
    /// The verification email was sent
    Sent,
    /// The email address is already verified
    AlreadyVerified,
}

/// The payload of the `sendVerificationEmail` mutation
#[derive(Description)]
enum SendVerificationEmailPayload {
    Sent(mas_data_model::UserEmail),
    AlreadyVerified(mas_data_model::UserEmail),
}

#[Object(use_type_description)]
impl SendVerificationEmailPayload {
    /// Status of the operation
    async fn status(&self) -> SendVerificationEmailStatus {
        match self {
            SendVerificationEmailPayload::Sent(_) => SendVerificationEmailStatus::Sent,
            SendVerificationEmailPayload::AlreadyVerified(_) => {
                SendVerificationEmailStatus::AlreadyVerified
            }
        }
    }

    /// The email address to which the verification email was sent
    async fn email(&self) -> UserEmail {
        match self {
            SendVerificationEmailPayload::Sent(email)
            | SendVerificationEmailPayload::AlreadyVerified(email) => UserEmail(email.clone()),
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self, ctx: &Context<'_>) -> Result<User, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            SendVerificationEmailPayload::Sent(email)
            | SendVerificationEmailPayload::AlreadyVerified(email) => email.user_id,
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(User(user))
    }
}

/// The input for the `verifyEmail` mutation
#[derive(InputObject)]
struct VerifyEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
    /// The verification code
    code: String,
}

/// The status of the `verifyEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum VerifyEmailStatus {
    /// The email address was just verified
    Verified,
    /// The email address was already verified before
    AlreadyVerified,
    /// The verification code is invalid
    InvalidCode,
}

/// The payload of the `verifyEmail` mutation
#[derive(Description)]
enum VerifyEmailPayload {
    Verified(mas_data_model::UserEmail),
    AlreadyVerified(mas_data_model::UserEmail),
    InvalidCode,
}

#[Object(use_type_description)]
impl VerifyEmailPayload {
    /// Status of the operation
    async fn status(&self) -> VerifyEmailStatus {
        match self {
            VerifyEmailPayload::Verified(_) => VerifyEmailStatus::Verified,
            VerifyEmailPayload::AlreadyVerified(_) => VerifyEmailStatus::AlreadyVerified,
            VerifyEmailPayload::InvalidCode => VerifyEmailStatus::InvalidCode,
        }
    }

    /// The email address that was verified
    async fn email(&self) -> Option<UserEmail> {
        match self {
            VerifyEmailPayload::Verified(email) | VerifyEmailPayload::AlreadyVerified(email) => {
                Some(UserEmail(email.clone()))
            }
            VerifyEmailPayload::InvalidCode => None,
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            VerifyEmailPayload::Verified(email) | VerifyEmailPayload::AlreadyVerified(email) => {
                email.user_id
            }
            VerifyEmailPayload::InvalidCode => return Ok(None),
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(Some(User(user)))
    }
}

#[Object]
impl UserEmailMutations {
    /// Add an email address to the specified user
    async fn add_email(
        &self,
        ctx: &Context<'_>,
        input: AddEmailInput,
    ) -> Result<AddEmailPayload, async_graphql::Error> {
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
        let (added, user_email) = if let Some(user_email) = existing_user_email {
            (false, user_email)
        } else {
            let clock = state.clock();
            let mut rng = state.rng();

            let user_email = repo
                .user_email()
                .add(&mut rng, &clock, user, input.email)
                .await?;

            (true, user_email)
        };

        // Schedule a job to verify the email address if needed
        if user_email.confirmed_at.is_none() {
            repo.job()
                .schedule_job(VerifyEmailJob::new(&user_email))
                .await?;
        }

        repo.save().await?;

        let payload = if added {
            AddEmailPayload::Added(user_email)
        } else {
            AddEmailPayload::Exists(user_email)
        };
        Ok(payload)
    }

    /// Send a verification code for an email address
    async fn send_verification_email(
        &self,
        ctx: &Context<'_>,
        input: SendVerificationEmailInput,
    ) -> Result<SendVerificationEmailPayload, async_graphql::Error> {
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
        let needs_verification = user_email.confirmed_at.is_none();
        if needs_verification {
            repo.job()
                .schedule_job(VerifyEmailJob::new(&user_email))
                .await?;
        }

        repo.save().await?;

        let payload = if needs_verification {
            SendVerificationEmailPayload::Sent(user_email)
        } else {
            SendVerificationEmailPayload::AlreadyVerified(user_email)
        };
        Ok(payload)
    }

    /// Submit a verification code for an email address
    async fn verify_email(
        &self,
        ctx: &Context<'_>,
        input: VerifyEmailInput,
    ) -> Result<VerifyEmailPayload, async_graphql::Error> {
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
            return Ok(VerifyEmailPayload::AlreadyVerified(user_email));
        }

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers

        // Find the verification code
        let verification = repo
            .user_email()
            .find_verification_code(&clock, &user_email, &input.code)
            .await?
            .filter(|v| v.is_valid());

        let Some(verification) = verification else {
            return Ok(VerifyEmailPayload::InvalidCode);
        };

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

        Ok(VerifyEmailPayload::Verified(user_email))
    }
}
