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
    job::{DeactivateUserJob, JobRepositoryExt, ProvisionUserJob},
    user::UserRepository,
};
use tracing::{info, warn};

use crate::graphql::{
    model::{NodeType, User},
    state::ContextExt,
    UserId,
};

#[derive(Default)]
pub struct UserMutations {
    _private: (),
}

/// The input for the `addUser` mutation.
#[derive(InputObject)]
struct AddUserInput {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is valid.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in MAS to craft special
    /// tokens (like with admin access) for them
    skip_homeserver_check: Option<bool>,
}

/// The status of the `addUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum AddUserStatus {
    /// The user was added.
    Added,

    /// The user already exists.
    Exists,

    /// The username is reserved.
    Reserved,

    /// The username is invalid.
    Invalid,
}

/// The payload for the `addUser` mutation.
#[derive(Description)]
enum AddUserPayload {
    Added(mas_data_model::User),
    Exists(mas_data_model::User),
    Reserved,
    Invalid,
}

#[Object(use_type_description)]
impl AddUserPayload {
    /// Status of the operation
    async fn status(&self) -> AddUserStatus {
        match self {
            Self::Added(_) => AddUserStatus::Added,
            Self::Exists(_) => AddUserStatus::Exists,
            Self::Reserved => AddUserStatus::Reserved,
            Self::Invalid => AddUserStatus::Invalid,
        }
    }

    /// The user that was added.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Added(user) | Self::Exists(user) => Some(User(user.clone())),
            Self::Invalid | Self::Reserved => None,
        }
    }
}

/// The input for the `lockUser` mutation.
#[derive(InputObject)]
struct LockUserInput {
    /// The ID of the user to lock.
    user_id: ID,

    /// Permanently lock the user.
    deactivate: Option<bool>,
}

/// The status of the `lockUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum LockUserStatus {
    /// The user was locked.
    Locked,

    /// The user was not found.
    NotFound,
}

/// The payload for the `lockUser` mutation.
#[derive(Description)]
enum LockUserPayload {
    /// The user was locked.
    Locked(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl LockUserPayload {
    /// Status of the operation
    async fn status(&self) -> LockUserStatus {
        match self {
            Self::Locked(_) => LockUserStatus::Locked,
            Self::NotFound => LockUserStatus::NotFound,
        }
    }

    /// The user that was locked.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Locked(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `setCanRequestAdmin` mutation.
#[derive(InputObject)]
struct SetCanRequestAdminInput {
    /// The ID of the user to update.
    user_id: ID,

    /// Whether the user can request admin.
    can_request_admin: bool,
}

/// The payload for the `setCanRequestAdmin` mutation.
#[derive(Description)]
enum SetCanRequestAdminPayload {
    /// The user was updated.
    Updated(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl SetCanRequestAdminPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Updated(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `allowUserCrossSigningReset` mutation.
#[derive(InputObject)]
struct AllowUserCrossSigningResetInput {
    /// The ID of the user to update.
    user_id: ID,
}

/// The payload for the `allowUserCrossSigningReset` mutation.
#[derive(Description)]
enum AllowUserCrossSigningResetPayload {
    /// The user was updated.
    Allowed(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl AllowUserCrossSigningResetPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Allowed(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

// XXX: this should probably be moved somewhere else
fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.get(0..1) == Some("_") {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

#[Object]
impl UserMutations {
    /// Add a user. This is only available to administrators.
    async fn add_user(
        &self,
        ctx: &Context<'_>,
        input: AddUserInput,
    ) -> Result<AddUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        if let Some(user) = repo.user().find_by_username(&input.username).await? {
            return Ok(AddUserPayload::Exists(user));
        }

        // Do some basic check on the username
        if !username_valid(&input.username) {
            return Ok(AddUserPayload::Invalid);
        }

        // Ask the homeserver if the username is available
        let homeserver_available = state
            .homeserver_connection()
            .is_localpart_available(&input.username)
            .await?;

        if !homeserver_available {
            if !input.skip_homeserver_check.unwrap_or(false) {
                return Ok(AddUserPayload::Reserved);
            }

            // If we skipped the check, we still want to shout about it
            warn!("Skipped homeserver check for username {}", input.username);
        }

        let user = repo.user().add(&mut rng, &clock, input.username).await?;

        repo.job()
            .schedule_job(ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(AddUserPayload::Added(user))
    }

    /// Lock a user. This is only available to administrators.
    async fn lock_user(
        &self,
        ctx: &Context<'_>,
        input: LockUserInput,
    ) -> Result<LockUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(LockUserPayload::NotFound);
        };

        let deactivate = input.deactivate.unwrap_or(false);

        let user = repo.user().lock(&state.clock(), user).await?;

        if deactivate {
            info!("Scheduling deactivation of user {}", user.id);
            repo.job()
                .schedule_job(DeactivateUserJob::new(&user, deactivate))
                .await?;
        }

        repo.save().await?;

        Ok(LockUserPayload::Locked(user))
    }

    /// Set whether a user can request admin. This is only available to
    /// administrators.
    async fn set_can_request_admin(
        &self,
        ctx: &Context<'_>,
        input: SetCanRequestAdminInput,
    ) -> Result<SetCanRequestAdminPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(SetCanRequestAdminPayload::NotFound);
        };

        let user = repo
            .user()
            .set_can_request_admin(user, input.can_request_admin)
            .await?;

        repo.save().await?;

        Ok(SetCanRequestAdminPayload::Updated(user))
    }

    /// Temporarily allow user to reset their cross-signing keys.
    async fn allow_user_cross_signing_reset(
        &self,
        ctx: &Context<'_>,
        input: AllowUserCrossSigningResetInput,
    ) -> Result<AllowUserCrossSigningResetPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user = repo.user().lookup(user_id).await?;
        repo.cancel().await?;

        let Some(user) = user else {
            return Ok(AllowUserCrossSigningResetPayload::NotFound);
        };

        let conn = state.homeserver_connection();
        let mxid = conn.mxid(&user.username);

        conn.allow_cross_signing_reset(&mxid)
            .await
            .context("Failed to allow cross-signing reset")?;

        Ok(AllowUserCrossSigningResetPayload::Allowed(user))
    }
}
