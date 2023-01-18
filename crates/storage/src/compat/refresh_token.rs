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

use async_trait::async_trait;
use mas_data_model::{CompatAccessToken, CompatRefreshToken, CompatSession};
use rand_core::RngCore;
use ulid::Ulid;

use crate::Clock;

#[async_trait]
pub trait CompatRefreshTokenRepository: Send + Sync {
    type Error;

    /// Lookup a compat refresh token by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatRefreshToken>, Self::Error>;

    /// Find a compat refresh token by its token
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<CompatRefreshToken>, Self::Error>;

    /// Add a new compat refresh token to the database
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        compat_access_token: &CompatAccessToken,
        token: String,
    ) -> Result<CompatRefreshToken, Self::Error>;

    /// Consume a compat refresh token
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        compat_refresh_token: CompatRefreshToken,
    ) -> Result<CompatRefreshToken, Self::Error>;
}
