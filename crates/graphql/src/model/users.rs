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
    Context, Description, Enum, Object, ID,
};
use chrono::{DateTime, Utc};
use mas_storage::{
    compat::{CompatSessionFilter, CompatSsoLoginFilter, CompatSsoLoginRepository},
    oauth2::{OAuth2SessionFilter, OAuth2SessionRepository},
    upstream_oauth2::UpstreamOAuthLinkRepository,
    user::{BrowserSessionFilter, BrowserSessionRepository, UserEmailFilter, UserEmailRepository},
    Pagination, RepositoryAccess,
};

use super::{
    compat_sessions::CompatSsoLogin, BrowserSession, Cursor, NodeCursor, NodeType, OAuth2Session,
    UpstreamOAuth2Link,
};
use crate::{
    model::{
        browser_sessions::BrowserSessionState,
        compat_sessions::{CompatSessionState, CompatSessionType},
        matrix::MatrixUser,
        oauth::OAuth2SessionState,
        CompatSession,
    },
    state::ContextExt,
};

#[derive(Description)]
/// A user is an individual's account.
pub struct User(pub mas_data_model::User);

impl From<mas_data_model::User> for User {
    fn from(v: mas_data_model::User) -> Self {
        Self(v)
    }
}

impl From<mas_data_model::BrowserSession> for User {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v.user)
    }
}

#[Object(use_type_description)]
impl User {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::User.id(self.0.id)
    }

    /// Username chosen by the user.
    async fn username(&self) -> &str {
        &self.0.username
    }

    /// Access to the user's Matrix account information.
    async fn matrix(&self, ctx: &Context<'_>) -> Result<MatrixUser, async_graphql::Error> {
        let state = ctx.state();
        let conn = state.homeserver_connection();
        Ok(MatrixUser::load(conn, &self.0.username).await?)
    }

    /// Primary email address of the user.
    async fn primary_email(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<UserEmail>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_email = repo.user_email().get_primary(&self.0).await?.map(UserEmail);
        repo.cancel().await?;
        Ok(user_email)
    }

    /// Get the list of compatibility SSO logins, chronologically sorted
    async fn compat_sso_logins(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, CompatSsoLogin, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = CompatSsoLoginFilter::new().for_user(&self.0);

                let page = repo.compat_sso_login().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.compat_sso_login().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::CompatSsoLogin, u.id)),
                        CompatSsoLogin(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of compatibility sessions, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn compat_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions with the given state.")]
        state_param: Option<CompatSessionState>,

        #[graphql(name = "type", desc = "List only sessions with the given type.")]
        type_param: Option<CompatSessionType>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, CompatSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSession))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSession))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                // Build the query filter
                let filter = CompatSessionFilter::new().for_user(&self.0);
                let filter = match state_param {
                    Some(CompatSessionState::Active) => filter.active_only(),
                    Some(CompatSessionState::Finished) => filter.finished_only(),
                    None => filter,
                };
                let filter = match type_param {
                    Some(CompatSessionType::SsoLogin) => filter.sso_login_only(),
                    Some(CompatSessionType::Unknown) => filter.unknown_only(),
                    None => filter,
                };

                let page = repo.compat_session().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.compat_session().count(filter).await?)
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
                    .extend(page.edges.into_iter().map(|(session, sso_login)| {
                        Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::CompatSession, session.id)),
                            CompatSession(session, sso_login),
                        )
                    }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of active browser sessions, chronologically sorted
    async fn browser_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<BrowserSessionState>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, BrowserSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = BrowserSessionFilter::new().for_user(&self.0);
                let filter = match state_param {
                    Some(BrowserSessionState::Active) => filter.active_only(),
                    Some(BrowserSessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let page = repo.browser_session().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.browser_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::BrowserSession, u.id)),
                        BrowserSession(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of emails, chronologically sorted
    async fn emails(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only emails in the given state.")]
        state_param: Option<UserEmailState>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UserEmail, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = UserEmailFilter::new().for_user(&self.0);

                let filter = match state_param {
                    Some(UserEmailState::Pending) => filter.pending_only(),
                    Some(UserEmailState::Confirmed) => filter.verified_only(),
                    None => filter,
                };

                let page = repo.user_email().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.user_email().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UserEmail, u.id)),
                        UserEmail(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of OAuth 2.0 sessions, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn oauth2_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<OAuth2SessionState>,

        #[graphql(desc = "List only sessions for the given client.")] client: Option<ID>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, OAuth2Session, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let client = if let Some(id) = client {
                    // Load the client if we're filtering by it
                    let id = NodeType::OAuth2Client.extract_ulid(&id)?;
                    let client = repo
                        .oauth2_client()
                        .lookup(id)
                        .await?
                        .ok_or(async_graphql::Error::new("Unknown client ID"))?;

                    Some(client)
                } else {
                    None
                };

                let filter = OAuth2SessionFilter::new().for_user(&self.0);

                let filter = match state_param {
                    Some(OAuth2SessionState::Active) => filter.active_only(),
                    Some(OAuth2SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match client.as_ref() {
                    Some(client) => filter.for_client(client),
                    None => filter,
                };

                let page = repo.oauth2_session().list(filter, pagination).await?;

                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.oauth2_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );

                connection.edges.extend(page.edges.into_iter().map(|s| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::OAuth2Session, s.id)),
                        OAuth2Session(s),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of upstream OAuth 2.0 links
    async fn upstream_oauth2_links(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UpstreamOAuth2Link>, async_graphql::Error> {
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
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let page = repo
                    .upstream_oauth_link()
                    .list_paginated(&self.0, pagination)
                    .await?;

                repo.cancel().await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|s| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UpstreamOAuth2Link, s.id)),
                        UpstreamOAuth2Link::new(s),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

pub struct PreloadedTotalCount(Option<usize>);

#[Object]
impl PreloadedTotalCount {
    /// Identifies the total count of items in the connection.
    async fn total_count(&self) -> Result<usize, async_graphql::Error> {
        self.0
            .ok_or_else(|| async_graphql::Error::new("total count not preloaded"))
    }
}

/// A user email address
#[derive(Description)]
pub struct UserEmail(pub mas_data_model::UserEmail);

#[Object(use_type_description)]
impl UserEmail {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UserEmail.id(self.0.id)
    }

    /// Email address
    async fn email(&self) -> &str {
        &self.0.email
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the email address was confirmed. Is `null` if the email was never
    /// verified by the user.
    async fn confirmed_at(&self) -> Option<DateTime<Utc>> {
        self.0.confirmed_at
    }
}

/// The state of a compatibility session.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum UserEmailState {
    /// The email address is pending confirmation.
    Pending,

    /// The email address has been confirmed.
    Confirmed,
}
