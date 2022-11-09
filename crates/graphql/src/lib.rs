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

use async_graphql::{Context, Description, EmptyMutation, EmptySubscription};
use mas_axum_utils::SessionInfo;
use model::CreationEvent;
use sqlx::PgPool;

use self::model::{BrowserSession, Node, User};

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
}
