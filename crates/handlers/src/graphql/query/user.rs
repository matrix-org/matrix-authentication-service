// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use async_graphql::{Context, Object, ID};

use crate::graphql::{
    model::{NodeType, User},
    state::ContextExt as _,
    UserId,
};

#[derive(Default)]
pub struct UserQuery;

#[Object]
impl UserQuery {
    /// Fetch a user by its ID.
    pub async fn user(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<User>, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&id)?;

        let requester = ctx.requester();
        if !requester.is_owner_or_admin(&UserId(id)) {
            return Ok(None);
        }

        // We could avoid the database lookup if the requester is the user we're looking
        // for but that would make the code more complex and we're not very
        // concerned about performance yet
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let user = repo.user().lookup(id).await?;
        repo.cancel().await?;

        Ok(user.map(User))
    }

    /// Fetch a user by its username.
    async fn user_by_username(
        &self,
        ctx: &Context<'_>,
        username: String,
    ) -> Result<Option<User>, async_graphql::Error> {
        let requester = ctx.requester();
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user = repo.user().find_by_username(&username).await?;
        let Some(user) = user else {
            // We don't want to leak the existence of a user
            return Ok(None);
        };

        // Users can only see themselves, except for admins
        if !requester.is_owner_or_admin(&user) {
            return Ok(None);
        }

        Ok(Some(User(user)))
    }
}
