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

use crate::{repository_impl, Clock};

/// A [`CompatRefreshTokenRepository`] helps interacting with
/// [`CompatRefreshToken`] saved in the storage backend
#[async_trait]
pub trait CompatRefreshTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a compat refresh token by its ID
    ///
    /// Returns the compat refresh token if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the compat refresh token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatRefreshToken>, Self::Error>;

    /// Find a compat refresh token by its token
    ///
    /// Returns the compat refresh token if found, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `refresh_token`: The token of the compat refresh token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<CompatRefreshToken>, Self::Error>;

    /// Add a new compat refresh token to the database
    ///
    /// Returns the newly created compat refresh token
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `compat_session`: The compat session associated with this refresh
    ///   token
    /// * `compat_access_token`: The compat access token created alongside this
    ///   refresh token
    /// * `token`: The token of the refresh token
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        compat_access_token: &CompatAccessToken,
        token: String,
    ) -> Result<CompatRefreshToken, Self::Error>;

    /// Consume a compat refresh token
    ///
    /// Returns the consumed compat refresh token
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `compat_refresh_token`: The compat refresh token to consume
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        compat_refresh_token: CompatRefreshToken,
    ) -> Result<CompatRefreshToken, Self::Error>;
}

repository_impl!(CompatRefreshTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatRefreshToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<CompatRefreshToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        compat_access_token: &CompatAccessToken,
        token: String,
    ) -> Result<CompatRefreshToken, Self::Error>;

    async fn consume(
        &mut self,
        clock: &dyn Clock,
        compat_refresh_token: CompatRefreshToken,
    ) -> Result<CompatRefreshToken, Self::Error>;
);
