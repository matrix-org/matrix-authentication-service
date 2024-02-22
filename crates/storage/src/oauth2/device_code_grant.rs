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
use chrono::Duration;
use mas_data_model::{BrowserSession, Client, DeviceCodeGrant, Session, UserAgent};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock};

/// Parameters used to create a new [`DeviceCodeGrant`]
pub struct OAuth2DeviceCodeGrantParams<'a> {
    /// The client which requested the device code grant
    pub client: &'a Client,

    /// The scope requested by the client
    pub scope: Scope,

    /// The device code which the client uses to poll for authorisation
    pub device_code: String,

    /// The user code which the client uses to display to the user
    pub user_code: String,

    /// After how long the device code expires
    pub expires_in: Duration,

    /// IP address from which the request was made
    pub ip_address: Option<IpAddr>,

    /// The user agent from which the request was made
    pub user_agent: Option<UserAgent>,
}

/// An [`OAuth2DeviceCodeGrantRepository`] helps interacting with
/// [`DeviceCodeGrant`] saved in the storage backend.
#[async_trait]
pub trait OAuth2DeviceCodeGrantRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Create a new device code grant
    ///
    /// Returns the newly created device code grant
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator
    /// * `clock`: The clock used to generate timestamps
    /// * `params`: The parameters used to create the device code grant. See the
    ///   fields of [`OAuth2DeviceCodeGrantParams`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: OAuth2DeviceCodeGrantParams<'_>,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    /// Lookup a device code grant by its ID
    ///
    /// Returns the device code grant if found, [`None`] otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the device code grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    /// Lookup a device code grant by its device code
    ///
    /// Returns the device code grant if found, [`None`] otherwise
    ///
    /// # Parameters
    ///
    /// * `device_code`: The device code of the device code grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    /// Lookup a device code grant by its user code
    ///
    /// Returns the device code grant if found, [`None`] otherwise
    ///
    /// # Parameters
    ///
    /// * `user_code`: The user code of the device code grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    /// Mark the device code grant as fulfilled with the given browser session
    ///
    /// Returns the updated device code grant
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `device_code_grant`: The device code grant to fulfill
    /// * `browser_session`: The browser session which was used to fulfill the
    ///   device code grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// device code grant is not in the [`Pending`] state
    ///
    /// [`Pending`]: mas_data_model::DeviceCodeGrantState::Pending
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    /// Mark the device code grant as rejected with the given browser session
    ///
    /// Returns the updated device code grant
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `device_code_grant`: The device code grant to reject
    /// * `browser_session`: The browser session which was used to reject the
    ///   device code grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// device code grant is not in the [`Pending`] state
    ///
    /// [`Pending`]: mas_data_model::DeviceCodeGrantState::Pending
    async fn reject(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    /// Mark the device code grant as exchanged and store the session which was
    /// created
    ///
    /// Returns the updated device code grant
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `device_code_grant`: The device code grant to exchange
    /// * `session`: The OAuth 2.0 session which was created
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// device code grant is not in the [`Fulfilled`] state
    ///
    /// [`Fulfilled`]: mas_data_model::DeviceCodeGrantState::Fulfilled
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        session: &Session,
    ) -> Result<DeviceCodeGrant, Self::Error>;
}

repository_impl!(OAuth2DeviceCodeGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: OAuth2DeviceCodeGrantParams<'_>,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    async fn find_by_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    async fn find_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error>;

    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    async fn reject(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error>;

    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        session: &Session,
    ) -> Result<DeviceCodeGrant, Self::Error>;
);
