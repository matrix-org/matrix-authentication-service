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

//! Repositories to interact with all kinds of sessions

use async_trait::async_trait;
use mas_data_model::{CompatSession, Session, User};

use crate::{repository_impl, Page, Pagination};

/// The state of a session
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSessionState {
    /// The session is active
    Active,
    /// The session is finished
    Finished,
}

impl AppSessionState {
    /// Returns [`true`] if we're looking for active sessions
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns [`true`] if we're looking for finished sessions
    #[must_use]
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// An [`AppSession`] is either a [`CompatSession`] or an OAuth 2.0 [`Session`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppSession {
    /// A compatibility layer session
    Compat(Box<CompatSession>),

    /// An OAuth 2.0 session
    OAuth2(Box<Session>),
}

/// Filtering parameters for application sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AppSessionFilter<'a> {
    user: Option<&'a User>,
    state: Option<AppSessionState>,
}

impl<'a> AppSessionFilter<'a> {
    /// Create a new [`AppSessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user who owns the compatibility sessions
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

    /// Only return active compatibility sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(AppSessionState::Active);
        self
    }

    /// Only return finished compatibility sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(AppSessionState::Finished);
        self
    }

    /// Get the state filter
    #[must_use]
    pub fn state(&self) -> Option<AppSessionState> {
        self.state
    }
}

/// A [`AppSessionRepository`] helps interacting with both [`CompatSession`] and
/// OAuth 2.0 [`Session`] at the same time saved in the storage backend
#[async_trait]
pub trait AppSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// List [`AppSession`] with the given filter and pagination
    ///
    /// Returns a page of [`AppSession`] matching the given filter
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
        filter: AppSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<AppSession>, Self::Error>;

    /// Count the number of [`AppSession`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error>;
}

repository_impl!(AppSessionRepository:
    async fn list(
        &mut self,
        filter: AppSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<AppSession>, Self::Error>;

    async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error>;
);
