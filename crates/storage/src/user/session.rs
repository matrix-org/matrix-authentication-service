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
use mas_data_model::{BrowserSession, Password, UpstreamOAuthLink, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, repository_impl, Clock, Pagination};

/// A [`BrowserSessionRepository`] helps interacting with [`BrowserSession`]
/// saved in the storage backend
#[async_trait]
pub trait BrowserSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`BrowserSession`] by its ID
    ///
    /// Returns `None` if the session is not found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the session to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error>;

    /// Create a new [`BrowserSession`] for a [`User`]
    ///
    /// Returns the newly created [`BrowserSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The user to create the session for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
    ) -> Result<BrowserSession, Self::Error>;

    /// Finish a [`BrowserSession`]
    ///
    /// Returns the finished session
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user_session`: The session to finish
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error>;

    /// List active [`BrowserSession`] for a [`User`] with the given pagination
    ///
    /// # Parameters
    ///
    /// * `user`: The user to list the sessions for
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list_active_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error>;

    /// Count active [`BrowserSession`] for a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The user to count the sessions for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count_active(&mut self, user: &User) -> Result<usize, Self::Error>;

    /// Authenticate a [`BrowserSession`] with the given [`Password`]
    ///
    /// Returns the updated [`BrowserSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user_session`: The session to authenticate
    /// * `user_password`: The password which was used to authenticate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        user_password: &Password,
    ) -> Result<BrowserSession, Self::Error>;

    /// Authenticate a [`BrowserSession`] with the given [`UpstreamOAuthLink`]
    ///
    /// Returns the updated [`BrowserSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user_session`: The session to authenticate
    /// * `upstream_oauth_link`: The upstream OAuth link which was used to
    ///   authenticate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        upstream_oauth_link: &UpstreamOAuthLink,
    ) -> Result<BrowserSession, Self::Error>;
}

repository_impl!(BrowserSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
    ) -> Result<BrowserSession, Self::Error>;
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error>;
    async fn list_active_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error>;
    async fn count_active(&mut self, user: &User) -> Result<usize, Self::Error>;

    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        user_password: &Password,
    ) -> Result<BrowserSession, Self::Error>;

    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        upstream_oauth_link: &UpstreamOAuthLink,
    ) -> Result<BrowserSession, Self::Error>;
);
