// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! Repositories to interact with entities related to user accounts

use async_trait::async_trait;
use mas_data_model::User;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock};

mod email;
mod password;
mod session;

pub use self::{
    email::{UserEmailFilter, UserEmailRepository},
    password::UserPasswordRepository,
    session::{BrowserSessionFilter, BrowserSessionRepository},
};

/// A [`UserRepository`] helps interacting with [`User`] saved in the storage
/// backend
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`User`] by its ID
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;

    /// Find a [`User`] by its username
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `username`: The username of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error>;

    /// Create a new [`User`]
    ///
    /// Returns the newly created [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator to generate the [`User`] ID
    /// * `clock`: The clock used to generate timestamps
    /// * `username`: The username of the [`User`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error>;

    /// Check if a [`User`] exists
    ///
    /// Returns `true` if the [`User`] exists, `false` otherwise
    ///
    /// # Parameters
    ///
    /// * `username`: The username of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error>;
}

repository_impl!(UserRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error>;
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error>;
);
