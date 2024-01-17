// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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

//! Repositories to interact with entities related to the upstream OAuth 2.0
//! providers

mod link;
mod provider;
mod session;

pub use self::{
    link::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
    provider::{
        UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    },
    session::UpstreamOAuthSessionRepository,
};
