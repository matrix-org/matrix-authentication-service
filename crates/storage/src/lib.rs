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

//! Interactions with the storage backend
//!
//! This crate provides a set of traits that can be implemented to interact with
//! the storage backend. Those traits are called repositories and are grouped by
//! the type of data they manage.
//!
//! Each of those reposotories can be accessed via the [`RepositoryAccess`]
//! trait. This trait can be wrapped in a [`BoxRepository`] to allow using it
//! without caring about the underlying storage backend, and without carrying
//! around the generic type parameter.
//!
//! This crate also defines a [`Clock`] trait that can be used to abstract the
//! way the current time is retrieved. It has two implementation:
//! [`SystemClock`] that uses the system time and [`MockClock`] which is useful
//! for testing.
//!
//! [`MockClock`]: crate::clock::MockClock
//!
//! # Defining a new repository
//!
//! To define a new repository, you have to:
//!   1. Define a new (async) repository trait, with the methods you need
//!   2. Write an implementation of this trait for each storage backend you want
//!      (currently only for [`mas-storage-pg`])
//!   3. Make it accessible via the [`RepositoryAccess`] trait
//!
//! The repository trait definition should look like this:
//!
//! ```rust
//! # use async_trait::async_trait;
//! # use ulid::Ulid;
//! # use rand_core::RngCore;
//! # use mas_storage::Clock;
//! #
//! # // A fake data structure, usually defined in mas-data-model
//! # struct FakeData {
//! #    id: Ulid,
//! # }
//! #
//! # // A fake empty macro, to replace `mas_storage::repository_impl`
//! # macro_rules! repository_impl { ($($tok:tt)*) => {} }
//!
//! #[async_trait]
//! pub trait FakeDataRepository: Send + Sync {
//!     /// The error type returned by the repository
//!     type Error;
//!
//!     /// Lookup a [`FakeData`] by its ID
//!     ///
//!     /// Returns `None` if no [`FakeData`] was found
//!     ///
//!     /// # Parameters
//!     ///
//!     /// * `id`: The ID of the [`FakeData`] to lookup
//!     ///
//!     /// # Errors
//!     ///
//!     /// Returns [`Self::Error`] if the underlying repository fails
//!     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error>;
//!
//!     /// Create a new [`FakeData`]
//!     ///
//!     /// Returns the newly-created [`FakeData`].
//!     ///
//!     /// # Parameters
//!     ///
//!     /// * `rng`: The random number generator to use
//!     /// * `clock`: The clock used to generate timestamps
//!     ///
//!     /// # Errors
//!     ///
//!     /// Returns [`Self::Error`] if the underlying repository fails
//!     async fn add(
//!         &mut self,
//!         rng: &mut (dyn RngCore + Send),
//!         clock: &dyn Clock,
//!     ) -> Result<FakeData, Self::Error>;
//! }
//!
//! repository_impl!(FakeDataRepository:
//!     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error>;
//!     async fn add(
//!         &mut self,
//!         rng: &mut (dyn RngCore + Send),
//!         clock: &dyn Clock,
//!     ) -> Result<FakeData, Self::Error>;
//! );
//! ```
//!
//! Four things to note with the implementation:
//!
//!   1. It defined an assocated error type, and all functions are faillible,
//!      and use that error type
//!   2. Lookups return an `Result<Option<T>, Self::Error>`, because 'not found'
//!      errors are usually cases that are handled differently
//!   3. Operations that need to record the current type use a [`Clock`]
//!      parameter. Operations that need to generate new IDs also use a random
//!      number generator.
//!   4. All the methods use an `&mut self`. This is ensures only one operation
//!      is done at a time on a single repository instance.
//!
//! Then update the [`RepositoryAccess`] trait to make the new repository
//! available:
//!
//! ```rust
//! # trait FakeDataRepository {
//! #     type Error;
//! # }
//!
//! /// Access the various repositories the backend implements.
//! pub trait RepositoryAccess: Send {
//!     /// The backend-specific error type used by each repository.
//!     type Error: std::error::Error + Send + Sync + 'static;
//!
//!     // ...other repositories...
//!
//!     /// Get a [`FakeDataRepository`]
//!     fn fake_data<'c>(&'c mut self) -> Box<dyn FakeDataRepository<Error = Self::Error> + 'c>;
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    clippy::future_not_send,
    rustdoc::broken_intra_doc_links,
    missing_docs
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod clock;
pub mod pagination;
pub(crate) mod repository;
mod utils;

pub mod app_session;
pub mod compat;
pub mod job;
pub mod oauth2;
pub mod upstream_oauth2;
pub mod user;

pub use self::{
    clock::{Clock, SystemClock},
    pagination::{Page, Pagination},
    repository::{
        BoxRepository, Repository, RepositoryAccess, RepositoryError, RepositoryTransaction,
    },
    utils::{BoxClock, BoxRng, MapErr},
};
