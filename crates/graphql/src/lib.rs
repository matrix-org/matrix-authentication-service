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

use std::time::Duration;

use async_graphql::Context;
use mas_axum_utils::SessionInfo;
use sqlx::PgPool;
use tokio_stream::{Stream, StreamExt};

pub type Schema = async_graphql::Schema<Query, Mutation, Subscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<Query, Mutation, Subscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(Query::new(), Mutation::new(), Subscription::new())
}

#[derive(Default)]
pub struct Query {
    _private: (),
}

impl Query {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_graphql::Object]
impl Query {
    /// A simple property which uses the DB pool and the current session
    async fn username(&self, ctx: &Context<'_>) -> Result<Option<String>, async_graphql::Error> {
        let database = ctx.data::<PgPool>()?;
        let session_info = ctx.data::<SessionInfo>()?;
        let mut conn = database.acquire().await?;
        let session = session_info.load_session(&mut conn).await?;

        Ok(session.map(|s| s.user.username))
    }
}

#[derive(Default)]
pub struct Mutation {
    _private: (),
}

impl Mutation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_graphql::Object]
impl Mutation {
    /// A dummy mutation so that the mutation object is not empty
    async fn hello(&self) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Subscription {
    _private: (),
}

impl Subscription {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_graphql::Subscription]
impl Subscription {
    /// A dump subscription to try out the websocket
    async fn integers(&self, #[graphql(default = 1)] step: i32) -> impl Stream<Item = i32> {
        let mut value = 0;
        tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(1)))
            .map(move |_| {
                value += step;
                value
            })
    }
}
