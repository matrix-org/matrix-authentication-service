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

mod browser_session;
mod compat_session;
mod matrix;
mod oauth2_session;
mod user;
mod user_email;

use async_graphql::MergedObject;

/// The mutations root of the GraphQL interface.
#[derive(Default, MergedObject)]
pub struct Mutation(
    user_email::UserEmailMutations,
    user::UserMutations,
    oauth2_session::OAuth2SessionMutations,
    compat_session::CompatSessionMutations,
    browser_session::BrowserSessionMutations,
    matrix::MatrixMutations,
);

impl Mutation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
