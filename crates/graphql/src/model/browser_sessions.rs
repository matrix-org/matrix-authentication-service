// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use async_graphql::{
    connection::{query, Connection, Edge, OpaqueCursor},
    Context, Description, Object, ID,
};
use chrono::{DateTime, Utc};
use mas_data_model::Device;
use mas_storage::{
    app_session::AppSessionFilter, user::BrowserSessionRepository, Pagination, RepositoryAccess,
};

use super::{
    AppSession, CompatSession, Cursor, NodeCursor, NodeType, OAuth2Session, PreloadedTotalCount,
    SessionState, User, UserAgent,
};
use crate::state::ContextExt;

/// A browser session represents a logged in user in a browser.
#[derive(Description)]
pub struct BrowserSession(pub mas_data_model::BrowserSession);

impl From<mas_data_model::BrowserSession> for BrowserSession {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v)
    }
}

#[Object(use_type_description)]
impl BrowserSession {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::BrowserSession.id(self.0.id)
    }

    /// The user logged in this session.
    async fn user(&self) -> User {
        User(self.0.user.clone())
    }

    /// The most recent authentication of this session.
    async fn last_authentication(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<Authentication>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&self.0)
            .await?;

        repo.cancel().await?;

        Ok(last_authentication.map(Authentication))
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the session was finished.
    pub async fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.0.finished_at
    }

    /// The state of the session.
    pub async fn state(&self) -> SessionState {
        if self.0.finished_at.is_some() {
            SessionState::Finished
        } else {
            SessionState::Active
        }
    }

    /// The user-agent with which the session was created.
    pub async fn user_agent(&self) -> Option<UserAgent> {
        self.0.user_agent.clone().map(|ua| ua.into())
    }

    /// The last IP address used by the session.
    pub async fn last_active_ip(&self) -> Option<String> {
        self.0.last_active_ip.map(|ip| ip.to_string())
    }

    /// The last time the session was active.
    pub async fn last_active_at(&self) -> Option<DateTime<Utc>> {
        self.0.last_active_at
    }

    /// Get the list of both compat and OAuth 2.0 sessions started by this
    /// browser session, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn app_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<SessionState>,

        #[graphql(name = "device", desc = "List only sessions for the given device.")]
        device_param: Option<String>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, AppSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_types(&[NodeType::OAuth2Session, NodeType::CompatSession])
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_types(&[NodeType::OAuth2Session, NodeType::CompatSession])
                    })
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let device_param = device_param.map(Device::try_from).transpose()?;

                let filter = AppSessionFilter::new().for_browser_session(&self.0);

                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match device_param.as_ref() {
                    Some(device) => filter.for_device(device),
                    None => filter,
                };

                let page = repo.app_session().list(filter, pagination).await?;

                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.app_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );

                connection
                    .edges
                    .extend(page.edges.into_iter().map(|s| match s {
                        mas_storage::app_session::AppSession::Compat(session) => Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::CompatSession, session.id)),
                            AppSession::CompatSession(Box::new(CompatSession::new(*session))),
                        ),
                        mas_storage::app_session::AppSession::OAuth2(session) => Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::OAuth2Session, session.id)),
                            AppSession::OAuth2Session(Box::new(OAuth2Session(*session))),
                        ),
                    }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

/// An authentication records when a user enter their credential in a browser
/// session.
#[derive(Description)]
pub struct Authentication(pub mas_data_model::Authentication);

#[Object(use_type_description)]
impl Authentication {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::Authentication.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}
