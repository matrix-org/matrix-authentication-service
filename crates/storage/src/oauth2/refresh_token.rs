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
use mas_data_model::{AccessToken, RefreshToken, Session};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock};

/// An [`OAuth2RefreshTokenRepository`] helps interacting with [`RefreshToken`]
/// saved in the storage backend
#[async_trait]
pub trait OAuth2RefreshTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a refresh token by its ID
    ///
    /// Returns `None` if no [`RefreshToken`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`RefreshToken`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error>;

    /// Find a refresh token by its token
    ///
    /// Returns `None` if no [`RefreshToken`] was found
    ///
    /// # Parameters
    ///
    /// * `token`: The token of the [`RefreshToken`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error>;

    /// Add a new refresh token to the database
    ///
    /// Returns the newly created [`RefreshToken`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The [`Session`] in which to create the [`RefreshToken`]
    /// * `access_token`: The [`AccessToken`] created alongside this
    ///   [`RefreshToken`]
    /// * `refresh_token`: The refresh token to store
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error>;

    /// Consume a refresh token
    ///
    /// Returns the updated [`RefreshToken`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `refresh_token`: The [`RefreshToken`] to consume
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// token was already consumed
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;
}

repository_impl!(OAuth2RefreshTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error>;

    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;
);
