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

use async_graphql::{Context, Enum, InputObject, Object, ID};
use mas_storage::RepositoryAccess;

use crate::graphql::{
    model::{BrowserSession, NodeType},
    state::ContextExt,
};

#[derive(Default)]
pub struct BrowserSessionMutations {
    _private: (),
}

/// The input of the `endBrowserSession` mutation.
#[derive(InputObject)]
pub struct EndBrowserSessionInput {
    /// The ID of the session to end.
    browser_session_id: ID,
}

/// The payload of the `endBrowserSession` mutation.
pub enum EndBrowserSessionPayload {
    NotFound,
    Ended(Box<mas_data_model::BrowserSession>),
}

/// The status of the `endBrowserSession` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndBrowserSessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndBrowserSessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndBrowserSessionStatus {
        match self {
            Self::Ended(_) => EndBrowserSessionStatus::Ended,
            Self::NotFound => EndBrowserSessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn browser_session(&self) -> Option<BrowserSession> {
        match self {
            Self::Ended(session) => Some(BrowserSession(*session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl BrowserSessionMutations {
    async fn end_browser_session(
        &self,
        ctx: &Context<'_>,
        input: EndBrowserSessionInput,
    ) -> Result<EndBrowserSessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let browser_session_id =
            NodeType::BrowserSession.extract_ulid(&input.browser_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let clock = state.clock();

        let session = repo.browser_session().lookup(browser_session_id).await?;

        let Some(session) = session else {
            return Ok(EndBrowserSessionPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(EndBrowserSessionPayload::NotFound);
        }

        let session = repo.browser_session().finish(&clock, session).await?;

        repo.save().await?;

        Ok(EndBrowserSessionPayload::Ended(Box::new(session)))
    }
}
