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
use mas_data_model::{Password, User};
use rand_core::RngCore;

use crate::{repository_impl, Clock};

/// A [`UserPasswordRepository`] helps interacting with [`Password`] saved in
/// the storage backend
#[async_trait]
pub trait UserPasswordRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Get the active password for a user
    ///
    /// Returns `None` if the user has no password set
    ///
    /// # Parameters
    ///
    /// * `user`: The user to get the password for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error>;

    /// Set a new password for a user
    ///
    /// Returns the newly created [`Password`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The user to set the password for
    /// * `version`: The version of the hashing scheme used
    /// * `hashed_password`: The hashed password
    /// * `upgraded_from`: The password this password was upgraded from, if any
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error>;
}

repository_impl!(UserPasswordRepository:
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error>;
);
