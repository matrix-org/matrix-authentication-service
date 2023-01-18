// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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
use chrono::Duration;
use mas_data_model::{AccessToken, Session};
use rand::RngCore;
use ulid::Ulid;

use crate::Clock;

#[async_trait]
pub trait OAuth2AccessTokenRepository: Send + Sync {
    type Error;

    /// Lookup an access token by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error>;

    /// Find an access token by its token
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<AccessToken>, Self::Error>;

    /// Add a new access token to the database
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        session: &Session,
        access_token: String,
        expires_after: Duration,
    ) -> Result<AccessToken, Self::Error>;

    /// Revoke an access token
    async fn revoke(
        &mut self,
        clock: &Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error>;

    /// Cleanup expired access tokens
    async fn cleanup_expired(&mut self, clock: &Clock) -> Result<usize, Self::Error>;
}
