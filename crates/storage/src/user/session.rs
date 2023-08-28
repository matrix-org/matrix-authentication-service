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
use mas_data_model::{
    Authentication, BrowserSession, Password, UpstreamOAuthAuthorizationSession, User,
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, repository_impl, Clock, Pagination};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserSessionState {
    Active,
    Finished,
}

impl BrowserSessionState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// Filter parameters for listing browser sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BrowserSessionFilter<'a> {
    user: Option<&'a User>,
    state: Option<BrowserSessionState>,
}

impl<'a> BrowserSessionFilter<'a> {
    /// Create a new [`BrowserSessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user who owns the browser sessions
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// Only return active browser sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(BrowserSessionState::Active);
        self
    }

    /// Only return finished browser sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(BrowserSessionState::Finished);
        self
    }

    /// Get the state filter
    #[must_use]
    pub fn state(&self) -> Option<BrowserSessionState> {
        self.state
    }
}

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

    /// List [`BrowserSession`] with the given filter and pagination
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: BrowserSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error>;

    /// Count the number of [`BrowserSession`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: BrowserSessionFilter<'_>) -> Result<usize, Self::Error>;

    /// Authenticate a [`BrowserSession`] with the given [`Password`]
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
        user_session: &BrowserSession,
        user_password: &Password,
    ) -> Result<Authentication, Self::Error>;

    /// Authenticate a [`BrowserSession`] with the given
    /// [`UpstreamOAuthAuthorizationSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user_session`: The session to authenticate
    /// * `upstream_oauth_session`: The upstream OAuth session which was used to
    ///   authenticate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        upstream_oauth_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<Authentication, Self::Error>;

    /// Get the last successful authentication for a [`BrowserSession`]
    ///
    /// # Params
    ///
    /// * `user_session`: The session for which to get the last authentication
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn get_last_authentication(
        &mut self,
        user_session: &BrowserSession,
    ) -> Result<Option<Authentication>, Self::Error>;
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

    async fn list(
        &mut self,
        filter: BrowserSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error>;

    async fn count(&mut self, filter: BrowserSessionFilter<'_>) -> Result<usize, Self::Error>;

    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        user_password: &Password,
    ) -> Result<Authentication, Self::Error>;

    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        upstream_oauth_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<Authentication, Self::Error>;

    async fn get_last_authentication(
        &mut self,
        user_session: &BrowserSession,
    ) -> Result<Option<Authentication>, Self::Error>;
);
