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
use mas_data_model::{CompatSession, CompatSsoLogin, User};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::{pagination::Page, repository_impl, Clock, Pagination};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatSsoLoginState {
    Pending,
    Fulfilled,
    Exchanged,
}

impl CompatSsoLoginState {
    /// Returns [`true`] if we're looking for pending SSO logins
    #[must_use]
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns [`true`] if we're looking for fulfilled SSO logins
    #[must_use]
    pub fn is_fulfilled(self) -> bool {
        matches!(self, Self::Fulfilled)
    }

    /// Returns [`true`] if we're looking for exchanged SSO logins
    #[must_use]
    pub fn is_exchanged(self) -> bool {
        matches!(self, Self::Exchanged)
    }
}

/// Filter parameters for listing compat SSO logins
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CompatSsoLoginFilter<'a> {
    user: Option<&'a User>,
    state: Option<CompatSsoLoginState>,
}

impl<'a> CompatSsoLoginFilter<'a> {
    /// Create a new empty filter
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user who owns the SSO logins sessions
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

    /// Only return pending SSO logins
    #[must_use]
    pub fn pending_only(mut self) -> Self {
        self.state = Some(CompatSsoLoginState::Pending);
        self
    }

    /// Only return fulfilled SSO logins
    #[must_use]
    pub fn fulfilled_only(mut self) -> Self {
        self.state = Some(CompatSsoLoginState::Fulfilled);
        self
    }

    /// Only return exchanged SSO logins
    #[must_use]
    pub fn exchanged_only(mut self) -> Self {
        self.state = Some(CompatSsoLoginState::Exchanged);
        self
    }

    /// Get the state filter
    #[must_use]
    pub fn state(&self) -> Option<CompatSsoLoginState> {
        self.state
    }
}

/// A [`CompatSsoLoginRepository`] helps interacting with
/// [`CompatSsoLoginRepository`] saved in the storage backend
#[async_trait]
pub trait CompatSsoLoginRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a compat SSO login by its ID
    ///
    /// Returns the compat SSO login if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the compat SSO login to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSsoLogin>, Self::Error>;

    /// Find a compat SSO login by its login token
    ///
    /// Returns the compat SSO login if found, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `login_token`: The login token of the compat SSO login to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        login_token: &str,
    ) -> Result<Option<CompatSsoLogin>, Self::Error>;

    /// Start a new compat SSO login token
    ///
    /// Returns the newly created compat SSO login
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate the timestamps
    /// * `login_token`: The login token given to the client
    /// * `redirect_uri`: The redirect URI given by the client
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        login_token: String,
        redirect_uri: Url,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// Fulfill a compat SSO login by providing a compat session
    ///
    /// Returns the fulfilled compat SSO login
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate the timestamps
    /// * `compat_sso_login`: The compat SSO login to fulfill
    /// * `compat_session`: The compat session to associate with the compat SSO
    ///   login
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        compat_session: &CompatSession,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// Mark a compat SSO login as exchanged
    ///
    /// Returns the exchanged compat SSO login
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate the timestamps
    /// * `compat_sso_login`: The compat SSO login to mark as exchanged
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// List [`CompatSsoLogin`] with the given filter and pagination
    ///
    /// Returns a page of compat SSO logins
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
        filter: CompatSsoLoginFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<CompatSsoLogin>, Self::Error>;

    /// Count the number of [`CompatSsoLogin`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: CompatSsoLoginFilter<'_>) -> Result<usize, Self::Error>;
}

repository_impl!(CompatSsoLoginRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSsoLogin>, Self::Error>;

    async fn find_by_token(
        &mut self,
        login_token: &str,
    ) -> Result<Option<CompatSsoLogin>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        login_token: String,
        redirect_uri: Url,
    ) -> Result<CompatSsoLogin, Self::Error>;

    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        compat_session: &CompatSession,
    ) -> Result<CompatSsoLogin, Self::Error>;

    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
    ) -> Result<CompatSsoLogin, Self::Error>;

    async fn list(
        &mut self,
        filter: CompatSsoLoginFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<CompatSsoLogin>, Self::Error>;

    async fn count(&mut self, filter: CompatSsoLoginFilter<'_>) -> Result<usize, Self::Error>;
);
