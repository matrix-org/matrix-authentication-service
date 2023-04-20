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

mod model;
mod mutations;
mod query;
mod state;

pub use self::{
    model::{CreationEvent, Node},
    mutations::RootMutations,
    query::RootQuery,
    state::{BoxState, State},
};

pub type Schema = async_graphql::Schema<RootQuery, RootMutations, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<RootQuery, RootMutations, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(RootQuery::new(), RootMutations::new(), EmptySubscription)
        .register_output_type::<Node>()
        .register_output_type::<CreationEvent>()
}
