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
use mas_data_model::{BrowserSession, Client, Session, User};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, repository_impl, Clock, Pagination};

/// An [`OAuth2SessionRepository`] helps interacting with [`Session`]
/// saved in the storage backend
#[async_trait]
pub trait OAuth2SessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an [`Session`] by its ID
    ///
    /// Returns `None` if no [`Session`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`Session`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error>;

    /// Create a new [`Session`]
    ///
    /// Returns the newly created [`Session`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The [`Client`] which created the [`Session`]
    /// * `user_session`: The [`BrowserSession`] of the user which completed the
    ///   authorization
    /// * `scope`: The [`Scope`] of the [`Session`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user_session: &BrowserSession,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    /// Mark a [`Session`] as finished
    ///
    /// Returns the updated [`Session`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The [`Session`] to mark as finished
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish(&mut self, clock: &dyn Clock, session: Session)
        -> Result<Session, Self::Error>;

    /// Get a paginated list of [`Session`]s for a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to get the [`Session`]s for
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;
}

repository_impl!(OAuth2SessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user_session: &BrowserSession,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    async fn finish(&mut self, clock: &dyn Clock, session: Session)
        -> Result<Session, Self::Error>;

    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;
);
