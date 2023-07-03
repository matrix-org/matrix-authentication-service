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

use async_graphql::{Context, MergedObject, Object, ID};

use crate::{
    model::{Anonymous, BrowserSession, Node, NodeType, OAuth2Client, User, UserEmail},
    state::ContextExt,
};

mod upstream_oauth;
mod viewer;

use self::{upstream_oauth::UpstreamOAuthQuery, viewer::ViewerQuery};

/// The query root of the GraphQL interface.
#[derive(Default, MergedObject)]
pub struct Query(BaseQuery, UpstreamOAuthQuery, ViewerQuery);

impl Query {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default)]
struct BaseQuery;

// TODO: move the rest of the queries in separate modules
#[Object]
impl BaseQuery {
    /// Get the current logged in browser session
    #[graphql(deprecation = "Use `viewerSession` instead.")]
    async fn current_browser_session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let requester = ctx.requester();
        Ok(requester
            .browser_session()
            .cloned()
            .map(BrowserSession::from))
    }

    /// Get the current logged in user
    #[graphql(deprecation = "Use `viewer` instead.")]
    async fn current_user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let requester = ctx.requester();
        Ok(requester.user().cloned().map(User::from))
    }

    /// Fetch an OAuth 2.0 client by its ID.
    async fn oauth2_client(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<OAuth2Client>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::OAuth2Client.extract_ulid(&id)?;

        let mut repo = state.repository().await?;
        let client = repo.oauth2_client().lookup(id).await?;
        repo.cancel().await?;

        Ok(client.map(OAuth2Client))
    }

    /// Fetch a user by its ID.
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Result<Option<User>, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&id)?;
        let requester = ctx.requester();

        let Some(current_user) = requester.user() else {
            return Ok(None);
        };

        if current_user.id == id {
            Ok(Some(User(current_user.clone())))
        } else {
            Ok(None)
        }
    }

    /// Fetch a browser session by its ID.
    async fn browser_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::BrowserSession.extract_ulid(&id)?;
        let requester = ctx.requester();

        let Some(current_user) = requester.user() else {
            return Ok(None);
        };
        let mut repo = state.repository().await?;

        let browser_session = repo.browser_session().lookup(id).await?;

        repo.cancel().await?;

        let ret = browser_session.and_then(|browser_session| {
            if browser_session.user.id == current_user.id {
                Some(BrowserSession(browser_session))
            } else {
                None
            }
        });

        Ok(ret)
    }

    /// Fetch a user email by its ID.
    async fn user_email(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UserEmail>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::UserEmail.extract_ulid(&id)?;
        let requester = ctx.requester();

        let Some(current_user) = requester.user() else {
            return Ok(None);
        };
        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(id)
            .await?
            .filter(|e| e.user_id == current_user.id);

        repo.cancel().await?;

        Ok(user_email.map(UserEmail))
    }

    /// Fetches an object given its ID.
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>, async_graphql::Error> {
        // Special case for the anonymous user
        if id.as_str() == "anonymous" {
            return Ok(Some(Node::Anonymous(Box::new(Anonymous))));
        }

        let (node_type, _id) = NodeType::from_id(&id)?;

        let ret = match node_type {
            // TODO
            NodeType::Authentication
            | NodeType::CompatSession
            | NodeType::CompatSsoLogin
            | NodeType::OAuth2Session => None,

            NodeType::UpstreamOAuth2Provider => UpstreamOAuthQuery
                .upstream_oauth2_provider(ctx, id)
                .await?
                .map(|c| Node::UpstreamOAuth2Provider(Box::new(c))),

            NodeType::UpstreamOAuth2Link => UpstreamOAuthQuery
                .upstream_oauth2_link(ctx, id)
                .await?
                .map(|c| Node::UpstreamOAuth2Link(Box::new(c))),

            NodeType::OAuth2Client => self
                .oauth2_client(ctx, id)
                .await?
                .map(|c| Node::OAuth2Client(Box::new(c))),

            NodeType::UserEmail => self
                .user_email(ctx, id)
                .await?
                .map(|e| Node::UserEmail(Box::new(e))),

            NodeType::BrowserSession => self
                .browser_session(ctx, id)
                .await?
                .map(|s| Node::BrowserSession(Box::new(s))),

            NodeType::User => self.user(ctx, id).await?.map(|u| Node::User(Box::new(u))),
        };

        Ok(ret)
    }
}
