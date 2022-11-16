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
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use async_graphql::{Context, Description, EmptyMutation, EmptySubscription, ID};
use mas_axum_utils::SessionInfo;
use mas_storage::LookupResultExt;
use sqlx::PgPool;

use self::model::{BrowserSession, Node, NodeType, OAuth2Client, User, UserEmail};

mod model;

pub type Schema = async_graphql::Schema<RootQuery, EmptyMutation, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<RootQuery, EmptyMutation, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(RootQuery::new(), EmptyMutation, EmptySubscription)
        .register_output_type::<Node>()
    // TODO: ordering of interface implementations is not stable
    //.register_output_type::<CreationEvent>()
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
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        Ok(session.map(BrowserSession::from))
    }

    /// Get the current logged in user
    async fn current_user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        Ok(session.map(User::from))
    }

    /// Fetch an OAuth 2.0 client by its ID.
    async fn oauth2_client(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<OAuth2Client>, async_graphql::Error> {
        let id = NodeType::OAuth2Client.extract_ulid(&id)?;
        let database = ctx.data::<PgPool>()?;
        let mut conn = database.acquire().await?;

        let client = mas_storage::oauth2::client::lookup_client(&mut conn, id)
            .await
            .to_option()?;

        Ok(client.map(OAuth2Client))
    }

    /// Fetch a user by its ID.
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Result<Option<User>, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&id)?;
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        if current_user.data == id {
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
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        let browser_session = mas_storage::user::lookup_active_session(&mut conn, id)
            .await
            .to_option()?;

        let ret = browser_session.and_then(|browser_session| {
            if browser_session.user.data == current_user.data {
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
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        let Some(session) = session else { return Ok(None) };
        let current_user = session.user;

        let user_email = mas_storage::user::lookup_user_email_by_id(&mut conn, &current_user, id)
            .await
            .to_option()?;

        Ok(user_email.map(UserEmail))
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
