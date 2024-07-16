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

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, CompatSession, CompatSsoLogin, Device, User, UserAgent};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock, Page, Pagination};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatSessionState {
    Active,
    Finished,
}

impl CompatSessionState {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatSessionType {
    SsoLogin,
    Unknown,
}

impl CompatSessionType {
    /// Returns [`true`] if we're looking for SSO logins
    #[must_use]
    pub fn is_sso_login(self) -> bool {
        matches!(self, Self::SsoLogin)
    }

    /// Returns [`true`] if we're looking for unknown sessions
    #[must_use]
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Filter parameters for listing compatibility sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CompatSessionFilter<'a> {
    user: Option<&'a User>,
    browser_session: Option<&'a BrowserSession>,
    state: Option<CompatSessionState>,
    auth_type: Option<CompatSessionType>,
    device: Option<&'a Device>,
}

impl<'a> CompatSessionFilter<'a> {
    /// Create a new [`CompatSessionFilter`] with default values
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
    pub fn user(&self) -> Option<&'a User> {
        self.user
    }

    /// Set the device filter
    #[must_use]
    pub fn for_device(mut self, device: &'a Device) -> Self {
        self.device = Some(device);
        self
    }

    /// Get the device filter
    #[must_use]
    pub fn device(&self) -> Option<&'a Device> {
        self.device
    }

    /// Set the browser session filter
    #[must_use]
    pub fn for_browser_session(mut self, browser_session: &'a BrowserSession) -> Self {
        self.browser_session = Some(browser_session);
        self
    }

    /// Get the browser session filter
    #[must_use]
    pub fn browser_session(&self) -> Option<&'a BrowserSession> {
        self.browser_session
    }

    /// Only return active compatibility sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(CompatSessionState::Active);
        self
    }

    /// Only return finished compatibility sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(CompatSessionState::Finished);
        self
    }

    /// Get the state filter
    #[must_use]
    pub fn state(&self) -> Option<CompatSessionState> {
        self.state
    }

    /// Only return SSO login compatibility sessions
    #[must_use]
    pub fn sso_login_only(mut self) -> Self {
        self.auth_type = Some(CompatSessionType::SsoLogin);
        self
    }

    /// Only return unknown compatibility sessions
    #[must_use]
    pub fn unknown_only(mut self) -> Self {
        self.auth_type = Some(CompatSessionType::Unknown);
        self
    }

    /// Get the auth type filter
    #[must_use]
    pub fn auth_type(&self) -> Option<CompatSessionType> {
        self.auth_type
    }
}

/// A [`CompatSessionRepository`] helps interacting with
/// [`CompatSession`] saved in the storage backend
#[async_trait]
pub trait CompatSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a compat session by its ID
    ///
    /// Returns the compat session if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the compat session to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error>;

    /// Start a new compat session
    ///
    /// Returns the newly created compat session
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The user to create the compat session for
    /// * `device`: The device ID of this session
    /// * `browser_session`: The browser session which created this session
    /// * `is_synapse_admin`: Whether the session is a synapse admin session
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        browser_session: Option<&BrowserSession>,
        is_synapse_admin: bool,
    ) -> Result<CompatSession, Self::Error>;

    /// End a compat session
    ///
    /// Returns the ended compat session
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `compat_session`: The compat session to end
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error>;

    /// Mark all the [`CompatSession`] matching the given filter as finished
    ///
    /// Returns the number of sessions affected
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: CompatSessionFilter<'_>,
    ) -> Result<usize, Self::Error>;

    /// List [`CompatSession`] with the given filter and pagination
    ///
    /// Returns a page of compat sessions, with the associated SSO logins if any
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
        filter: CompatSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<(CompatSession, Option<CompatSsoLogin>)>, Self::Error>;

    /// Count the number of [`CompatSession`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: CompatSessionFilter<'_>) -> Result<usize, Self::Error>;

    /// Record a batch of [`CompatSession`] activity
    ///
    /// # Parameters
    ///
    /// * `activity`: A list of tuples containing the session ID, the last
    ///   activity timestamp and the IP address of the client
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn record_batch_activity(
        &mut self,
        activity: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error>;

    /// Record the user agent of a compat session
    ///
    /// # Parameters
    ///
    /// * `compat_session`: The compat session to record the user agent for
    /// * `user_agent`: The user agent to record
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn record_user_agent(
        &mut self,
        compat_session: CompatSession,
        user_agent: UserAgent,
    ) -> Result<CompatSession, Self::Error>;
}

repository_impl!(CompatSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        browser_session: Option<&BrowserSession>,
        is_synapse_admin: bool,
    ) -> Result<CompatSession, Self::Error>;

    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error>;

    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: CompatSessionFilter<'_>,
    ) -> Result<usize, Self::Error>;

    async fn list(
        &mut self,
        filter: CompatSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<(CompatSession, Option<CompatSsoLogin>)>, Self::Error>;

    async fn count(&mut self, filter: CompatSessionFilter<'_>) -> Result<usize, Self::Error>;

    async fn record_batch_activity(
        &mut self,
        activity: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error>;

    async fn record_user_agent(
        &mut self,
        compat_session: CompatSession,
        user_agent: UserAgent,
    ) -> Result<CompatSession, Self::Error>;
);
