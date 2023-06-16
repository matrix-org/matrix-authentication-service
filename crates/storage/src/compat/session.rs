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
use mas_data_model::{CompatSession, Device, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock};

/// A [`CompatSessionRepository`] helps interacting with
/// [`CompatSessionRepository`] saved in the storage backend
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
}

repository_impl!(CompatSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        is_synapse_admin: bool,
    ) -> Result<CompatSession, Self::Error>;

    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error>;
);
