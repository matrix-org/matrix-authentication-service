// Copyright 2022-2023 The Matrix.org Foundation C.I.C.
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

use async_graphql::EmptySubscription;
use mas_data_model::{BrowserSession, User};

mod model;
mod mutations;
mod query;
mod state;

pub use self::{
    model::{CreationEvent, Node},
    mutations::Mutation,
    query::Query,
    state::{BoxState, State},
};

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<Query, Mutation, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(Query::new(), Mutation::new(), EmptySubscription)
        .register_output_type::<Node>()
        .register_output_type::<CreationEvent>()
}

/// The identity of the requester.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Requester {
    /// The requester presented no authentication information.
    #[default]
    Anonymous,

    /// The requester is a browser session, stored in a cookie.
    BrowserSession(BrowserSession),
}

impl Requester {
    fn browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            Self::Anonymous => None,
        }
    }

    fn user(&self) -> Option<&User> {
        self.browser_session().map(|session| &session.user)
    }
}

impl From<BrowserSession> for Requester {
    fn from(session: BrowserSession) -> Self {
        Self::BrowserSession(session)
    }
}

impl<T> From<Option<T>> for Requester
where
    T: Into<Requester>,
{
    fn from(session: Option<T>) -> Self {
        session.map(Into::into).unwrap_or_default()
    }
}
