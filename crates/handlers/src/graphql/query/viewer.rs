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

use async_graphql::{Context, Object};

use crate::graphql::{
    model::{Viewer, ViewerSession},
    state::ContextExt,
    Requester,
};

#[derive(Default)]
pub struct ViewerQuery;

#[Object]
impl ViewerQuery {
    /// Get the viewer
    async fn viewer(&self, ctx: &Context<'_>) -> Viewer {
        let requester = ctx.requester();

        match requester {
            Requester::BrowserSession(session) => Viewer::user(session.user.clone()),
            Requester::OAuth2Session(tuple) => match &tuple.1 {
                Some(user) => Viewer::user(user.clone()),
                None => Viewer::anonymous(),
            },
            Requester::Anonymous => Viewer::anonymous(),
        }
    }

    /// Get the viewer's session
    async fn viewer_session(&self, ctx: &Context<'_>) -> ViewerSession {
        let requester = ctx.requester();

        match requester {
            Requester::BrowserSession(session) => ViewerSession::browser_session(*session.clone()),
            Requester::OAuth2Session(tuple) => ViewerSession::oauth2_session(tuple.0.clone()),
            Requester::Anonymous => ViewerSession::anonymous(),
        }
    }
}
