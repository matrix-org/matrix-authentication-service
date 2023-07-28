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

use crate::{
    model::{NodeType, User},
    state::ContextExt,
};

#[derive(Default)]
pub struct MatrixMutations {
    _private: (),
}

/// The input for the `addEmail` mutation
#[derive(InputObject)]
struct SetDisplayNameInput {
    /// The ID of the user to add the email address to
    user_id: ID,

    /// The display name to set. If `None`, the display name will be removed.
    display_name: Option<String>,
}

/// The status of the `setDisplayName` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum SetDisplayNameStatus {
    /// The display name was set
    Set,
    /// The display name is invalid
    Invalid,
}

/// The payload of the `setDisplayName` mutation
#[derive(Description)]
enum SetDisplayNamePayload {
    Set(User),
    Invalid,
}

#[Object(use_type_description)]
impl SetDisplayNamePayload {
    /// Status of the operation
    async fn status(&self) -> SetDisplayNameStatus {
        match self {
            SetDisplayNamePayload::Set(_) => SetDisplayNameStatus::Set,
            SetDisplayNamePayload::Invalid => SetDisplayNameStatus::Invalid,
        }
    }

    /// The user that was updated
    async fn user(&self) -> Option<&User> {
        match self {
            SetDisplayNamePayload::Set(user) => Some(user),
            SetDisplayNamePayload::Invalid => None,
        }
    }
}

#[Object]
impl MatrixMutations {
    /// Set the display name of a user
    async fn set_display_name(
        &self,
        ctx: &Context<'_>,
        input: SetDisplayNameInput,
    ) -> Result<SetDisplayNamePayload, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        let user = requester.user().context("Unauthorized")?;

        if user.id != id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let conn = state.homeserver_connection();
        let mxid = conn.mxid(&user.username);

        if let Some(display_name) = &input.display_name {
            // Let's do some basic validation on the display name
            if display_name.len() > 256 {
                return Ok(SetDisplayNamePayload::Invalid);
            }

            if display_name.is_empty() {
                return Ok(SetDisplayNamePayload::Invalid);
            }

            conn.set_displayname(&mxid, display_name)
                .await
                .context("Failed to set display name")?;
        } else {
            conn.unset_displayname(&mxid)
                .await
                .context("Failed to unset display name")?;
        }

        Ok(SetDisplayNamePayload::Set(User(user.clone())))
    }
}
