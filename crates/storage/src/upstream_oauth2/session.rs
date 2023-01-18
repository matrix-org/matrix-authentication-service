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

use async_trait::async_trait;
use mas_data_model::{UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProvider};
use rand_core::RngCore;
use ulid::Ulid;

use crate::Clock;

#[async_trait]
pub trait UpstreamOAuthSessionRepository: Send + Sync {
    type Error;

    /// Lookup a session by its ID
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error>;

    /// Add a session to the database
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state: String,
        code_challenge_verifier: Option<String>,
        nonce: String,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as completed and associate the given link
    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as consumed
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;
}
