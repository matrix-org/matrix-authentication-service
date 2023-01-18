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
use chrono::Duration;
use mas_data_model::{CompatAccessToken, CompatSession};
use rand_core::RngCore;
use ulid::Ulid;

use crate::Clock;

#[async_trait]
pub trait CompatAccessTokenRepository: Send + Sync {
    type Error;

    /// Lookup a compat access token by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatAccessToken>, Self::Error>;

    /// Find a compat access token by its token
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<CompatAccessToken>, Self::Error>;

    /// Add a new compat access token to the database
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        token: String,
        expires_after: Option<Duration>,
    ) -> Result<CompatAccessToken, Self::Error>;

    /// Set the expiration time of the compat access token to now
    async fn expire(
        &mut self,
        clock: &dyn Clock,
        compat_access_token: CompatAccessToken,
    ) -> Result<CompatAccessToken, Self::Error>;
}
