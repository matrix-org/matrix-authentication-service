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
use async_graphql::{Context, Enum, InputObject, Object, ID};
use mas_data_model::Device;
use mas_storage::{
    job::{DeleteDeviceJob, JobRepositoryExt},
    oauth2::OAuth2SessionRepository,
    RepositoryAccess,
};

use crate::{
    model::{NodeType, OAuth2Session},
    state::ContextExt,
};

#[derive(Default)]
pub struct OAuth2SessionMutations {
    _private: (),
}

/// The input of the `endOauth2Session` mutation.
#[derive(InputObject)]
pub struct EndOAuth2SessionInput {
    /// The ID of the session to end.
    oauth2_session_id: ID,
}

/// The payload of the `endOauth2Session` mutation.
pub enum EndOAuth2SessionPayload {
    NotFound,
    Ended(mas_data_model::Session),
}

/// The status of the `endOauth2Session` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndOAuth2SessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndOAuth2SessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndOAuth2SessionStatus {
        match self {
            Self::Ended(_) => EndOAuth2SessionStatus::Ended,
            Self::NotFound => EndOAuth2SessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn oauth2_session(&self) -> Option<OAuth2Session> {
        match self {
            Self::Ended(session) => Some(OAuth2Session(session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl OAuth2SessionMutations {
    async fn end_oauth2_session(
        &self,
        ctx: &Context<'_>,
        input: EndOAuth2SessionInput,
    ) -> Result<EndOAuth2SessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let oauth2_session_id = NodeType::OAuth2Session.extract_ulid(&input.oauth2_session_id)?;
        let requester = ctx.requester();

        let user = requester.user().context("Unauthorized")?;

        let mut repo = state.repository().await?;
        let clock = state.clock();

        let session = repo.oauth2_session().lookup(oauth2_session_id).await?;
        let Some(session) = session else {
            return Ok(EndOAuth2SessionPayload::NotFound);
        };

        let user_session = repo
            .browser_session()
            .lookup(session.user_session_id)
            .await?
            .context("Browser session not found")?;

        if user_session.user.id != user.id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // Scan the scopes of the session to find if there is any device that should be
        // deleted from the Matrix server.
        // TODO: this should be moved in a higher level "end oauth session" method.
        // XXX: this might not be the right semantic, but it's the best we
        // can do for now, since we're not explicitly storing devices for OAuth2
        // sessions.
        for scope in session.scope.iter() {
            if let Some(device) = Device::from_scope_token(scope) {
                // Schedule a job to delete the device.
                repo.job()
                    .schedule_job(DeleteDeviceJob::new(&user_session.user, &device))
                    .await?;
            }
        }

        let session = repo.oauth2_session().finish(&clock, session).await?;

        repo.save().await?;

        Ok(EndOAuth2SessionPayload::Ended(session))
    }
}
