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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuth2SessionState {
    Active,
    Finished,
}

impl OAuth2SessionState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// Filter parameters for listing OAuth 2.0 sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OAuth2SessionFilter<'a> {
    user: Option<&'a User>,
    client: Option<&'a Client>,
    state: Option<OAuth2SessionState>,
    scope: Option<&'a Scope>,
}

impl<'a> OAuth2SessionFilter<'a> {
    /// Create a new [`OAuth2SessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// List sessions for a specific user
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    ///
    /// Returns [`None`] if no user filter was set
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// List sessions for a specific client
    #[must_use]
    pub fn for_client(mut self, client: &'a Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Get the client filter
    ///
    /// Returns [`None`] if no client filter was set
    #[must_use]
    pub fn client(&self) -> Option<&Client> {
        self.client
    }

    /// Only return active sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(OAuth2SessionState::Active);
        self
    }

    /// Only return finished sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(OAuth2SessionState::Finished);
        self
    }

    /// Get the state filter
    ///
    /// Returns [`None`] if no state filter was set
    #[must_use]
    pub fn state(&self) -> Option<OAuth2SessionState> {
        self.state
    }

    /// Only return sessions with the given scope
    #[must_use]
    pub fn with_scope(mut self, scope: &'a Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Get the scope filter
    ///
    /// Returns [`None`] if no scope filter was set
    #[must_use]
    pub fn scope(&self) -> Option<&Scope> {
        self.scope
    }
}

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

    /// List [`Session`]s matching the given filter and pagination parameters
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;

    /// Count [`Session`]s matching the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error>;
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

    async fn list(
        &mut self,
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;

    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error>;
);
