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

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::broken_intra_doc_links,
    clippy::future_not_send
)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::unused_async
)]

use async_graphql::{
    connection::{query, Connection, Edge, OpaqueCursor},
    Context, Description, EmptyMutation, EmptySubscription, ID,
};
use mas_storage::{
    oauth2::OAuth2ClientRepository,
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
    user::{BrowserSessionRepository, UserEmailRepository},
    PgRepository, Repository,
};
use model::CreationEvent;
use sqlx::PgPool;

use self::model::{
    BrowserSession, Cursor, Node, NodeCursor, NodeType, OAuth2Client, UpstreamOAuth2Link,
    UpstreamOAuth2Provider, User, UserEmail,
};

mod model;

pub type Schema = async_graphql::Schema<RootQuery, EmptyMutation, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<RootQuery, EmptyMutation, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(RootQuery::new(), EmptyMutation, EmptySubscription)
        .register_output_type::<Node>()
        .register_output_type::<CreationEvent>()
}

/// The query root of the GraphQL interface.
#[derive(Default, Description)]
pub struct RootQuery {
    _private: (),
}

impl RootQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_graphql::Object(use_type_description)]
impl RootQuery {
    /// Get the current logged in browser session
    async fn current_browser_session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        Ok(session.map(BrowserSession::from))
    }

    /// Get the current logged in user
    async fn current_user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        Ok(session.map(User::from))
    }

    /// Fetch an OAuth 2.0 client by its ID.
    async fn oauth2_client(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<OAuth2Client>, async_graphql::Error> {
        let id = NodeType::OAuth2Client.extract_ulid(&id)?;
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        let client = repo.oauth2_client().lookup(id).await?;

        Ok(client.map(OAuth2Client))
    }

    /// Fetch a user by its ID.
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Result<Option<User>, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&id)?;
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        if current_user.id == id {
            Ok(Some(User(current_user)))
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
        let id = NodeType::BrowserSession.extract_ulid(&id)?;
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        let browser_session = repo.browser_session().lookup(id).await?;

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
        let id = NodeType::UserEmail.extract_ulid(&id)?;
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        let user_email = repo
            .user_email()
            .lookup(id)
            .await?
            .filter(|e| e.user_id == current_user.id);

        Ok(user_email.map(UserEmail))
    }

    /// Fetch an upstream OAuth 2.0 link by its ID.
    async fn upstream_oauth2_link(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UpstreamOAuth2Link>, async_graphql::Error> {
        let id = NodeType::UpstreamOAuth2Link.extract_ulid(&id)?;
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        let link = repo.upstream_oauth_link().lookup(id).await?;

        // Ensure that the link belongs to the current user
        let link = link.filter(|link| link.user_id == Some(current_user.id));

        Ok(link.map(UpstreamOAuth2Link::new))
    }

    /// Fetch an upstream OAuth 2.0 provider by its ID.
    async fn upstream_oauth2_provider(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UpstreamOAuth2Provider>, async_graphql::Error> {
        let id = NodeType::UpstreamOAuth2Provider.extract_ulid(&id)?;
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        let provider = repo.upstream_oauth_provider().lookup(id).await?;

        Ok(provider.map(UpstreamOAuth2Provider::new))
    }

    /// Get a list of upstream OAuth 2.0 providers.
    async fn upstream_oauth2_providers(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UpstreamOAuth2Provider>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Provider)
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Provider)
                    })
                    .transpose()?;

                let page = repo
                    .upstream_oauth_provider()
                    .list_paginated(before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|p| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UpstreamOAuth2Provider, p.id)),
                        UpstreamOAuth2Provider::new(p),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Fetches an object given its ID.
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>, async_graphql::Error> {
        let (node_type, _id) = NodeType::from_id(&id)?;

        let ret = match node_type {
            // TODO
            NodeType::Authentication
            | NodeType::CompatSession
            | NodeType::CompatSsoLogin
            | NodeType::OAuth2Session => None,

            NodeType::UpstreamOAuth2Provider => self
                .upstream_oauth2_provider(ctx, id)
                .await?
                .map(|c| Node::UpstreamOAuth2Provider(Box::new(c))),

            NodeType::UpstreamOAuth2Link => self
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
