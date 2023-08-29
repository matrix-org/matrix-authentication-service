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

use async_graphql::{Context, Object, Union, ID};
use mas_data_model::Device;
use mas_storage::{
    compat::CompatSessionRepository, oauth2::OAuth2SessionFilter, Pagination, RepositoryAccess,
};
use oauth2_types::scope::Scope;

use crate::{
    model::{CompatSession, NodeType, OAuth2Session},
    state::ContextExt,
    UserId,
};

#[derive(Default)]
pub struct SessionQuery;

/// A client session, either compat or OAuth 2.0
#[derive(Union)]
enum Session {
    CompatSession(Box<CompatSession>),
    OAuth2Session(Box<OAuth2Session>),
}

#[Object]
impl SessionQuery {
    /// Lookup a compat or OAuth 2.0 session
    async fn session(
        &self,
        ctx: &Context<'_>,
        user_id: ID,
        device_id: String,
    ) -> Result<Option<Session>, async_graphql::Error> {
        let user_id = NodeType::User.extract_ulid(&user_id)?;
        let requester = ctx.requester();
        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Ok(None);
        }

        let Ok(device) = Device::try_from(device_id) else {
            return Ok(None);
        };
        let state = ctx.state();
        let mut repo = state.repository().await?;

        // Lookup the user
        let Some(user) = repo.user().lookup(user_id).await? else {
            return Ok(None);
        };

        // First, try to find a compat session
        let compat_session = repo.compat_session().find_by_device(&user, &device).await?;
        if let Some(compat_session) = compat_session {
            repo.cancel().await?;

            // XXX: we should load the compat SSO login as well
            return Ok(Some(Session::CompatSession(Box::new(CompatSession(
                compat_session,
                None,
            )))));
        }

        // Then, try to find an OAuth 2.0 session. Because we don't have any dedicated
        // device column, we're looking up using the device scope.
        let scope = Scope::from_iter([device.to_scope_token()]);
        let filter = OAuth2SessionFilter::new()
            .for_user(&user)
            .active_only()
            .with_scope(&scope);
        // We only want most recent session
        let pagination = Pagination::last(1);
        let sessions = repo.oauth2_session().list(filter, pagination).await?;

        // It's technically possible to have multiple active OAuth 2.0 sessions. For
        // now, we just log it if it is the case
        if sessions.has_next_page {
            // XXX: should we bail out?
            tracing::warn!(
                "Found more than one active session with device {device} for user {user_id}"
            );
        }

        if let Some(session) = sessions.edges.into_iter().next() {
            repo.cancel().await?;
            return Ok(Some(Session::OAuth2Session(Box::new(OAuth2Session(
                session,
            )))));
        }
        repo.cancel().await?;

        Ok(None)
    }
}
