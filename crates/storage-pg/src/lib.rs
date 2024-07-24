// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
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

//! An implementation of the storage traits for a PostgreSQL database
//!
//! This backend uses [`sqlx`] to interact with the database. Most queries are
//! type-checked, using introspection data recorded in the `sqlx-data.json`
//! file. This file is generated by the `sqlx` CLI tool, and should be updated
//! whenever the database schema changes, or new queries are added.
//!
//! # Implementing a new repository
//!
//! When a new repository is defined in [`mas_storage`], it should be
//! implemented here, with the PostgreSQL backend.
//!
//! A typical implementation will look like this:
//!
//! ```rust
//! # use async_trait::async_trait;
//! # use ulid::Ulid;
//! # use rand::RngCore;
//! # use mas_storage::Clock;
//! # use mas_storage_pg::{DatabaseError, ExecuteExt};
//! # use sqlx::PgConnection;
//! # use uuid::Uuid;
//! #
//! # // A fake data structure, usually defined in mas-data-model
//! # #[derive(sqlx::FromRow)]
//! # struct FakeData {
//! #    id: Ulid,
//! # }
//! #
//! # // A fake repository trait, usually defined in mas-storage
//! # #[async_trait]
//! # pub trait FakeDataRepository: Send + Sync {
//! #     type Error;
//! #     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error>;
//! #     async fn add(
//! #         &mut self,
//! #         rng: &mut (dyn RngCore + Send),
//! #         clock: &dyn Clock,
//! #     ) -> Result<FakeData, Self::Error>;
//! # }
//! #
//! /// An implementation of [`FakeDataRepository`] for a PostgreSQL connection
//! pub struct PgFakeDataRepository<'c> {
//!     conn: &'c mut PgConnection,
//! }
//!
//! impl<'c> PgFakeDataRepository<'c> {
//!     /// Create a new [`FakeDataRepository`] from an active PostgreSQL connection
//!     pub fn new(conn: &'c mut PgConnection) -> Self {
//!         Self { conn }
//!     }
//! }
//!
//! #[derive(sqlx::FromRow)]
//! struct FakeDataLookup {
//!     fake_data_id: Uuid,
//! }
//!
//! impl From<FakeDataLookup> for FakeData {
//!     fn from(value: FakeDataLookup) -> Self {
//!         Self {
//!             id: value.fake_data_id.into(),
//!         }
//!     }
//! }
//!
//! #[async_trait]
//! impl<'c> FakeDataRepository for PgFakeDataRepository<'c> {
//!     type Error = DatabaseError;
//!
//!     #[tracing::instrument(
//!         name = "db.fake_data.lookup",
//!         skip_all,
//!         fields(
//!             db.query.text,
//!             fake_data.id = %id,
//!         ),
//!         err,
//!     )]
//!     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error> {
//!         // Note: here we would use the macro version instead, but it's not possible here in
//!         // this documentation example
//!         let res: Option<FakeDataLookup> = sqlx::query_as(
//!             r#"
//!                 SELECT fake_data_id
//!                 FROM fake_data
//!                 WHERE fake_data_id = $1
//!             "#,
//!         )
//!         .bind(Uuid::from(id))
//!         .traced()
//!         .fetch_optional(&mut *self.conn)
//!         .await?;
//!
//!         let Some(res) = res else { return Ok(None) };
//!
//!         Ok(Some(res.into()))
//!     }
//!
//!     #[tracing::instrument(
//!         name = "db.fake_data.add",
//!         skip_all,
//!         fields(
//!             db.query.text,
//!             fake_data.id,
//!         ),
//!         err,
//!     )]
//!     async fn add(
//!         &mut self,
//!         rng: &mut (dyn RngCore + Send),
//!         clock: &dyn Clock,
//!     ) -> Result<FakeData, Self::Error> {
//!         let created_at = clock.now();
//!         let id = Ulid::from_datetime_with_source(created_at.into(), rng);
//!         tracing::Span::current().record("fake_data.id", tracing::field::display(id));
//!
//!         // Note: here we would use the macro version instead, but it's not possible here in
//!         // this documentation example
//!         sqlx::query(
//!             r#"
//!                 INSERT INTO fake_data (id)
//!                 VALUES ($1)
//!             "#,
//!         )
//!         .bind(Uuid::from(id))
//!         .traced()
//!         .execute(&mut *self.conn)
//!         .await?;
//!
//!         Ok(FakeData {
//!             id,
//!         })
//!     }
//! }
//! ```
//!
//! A few things to note with the implementation:
//!
//!  - All methods are traced, with an explicit, somewhat consistent name.
//!  - The SQL statement is included as attribute, by declaring a
//!    `db.query.text` attribute on the tracing span, and then calling
//!    [`ExecuteExt::traced`].
//!  - The IDs are all [`Ulid`], and generated from the clock and the random
//!    number generated passed as parameters. The generated IDs are recorded in
//!    the span.
//!  - The IDs are stored as [`Uuid`] in PostgreSQL, so conversions are required
//!  - "Not found" errors are handled by returning `Ok(None)` instead of an
//!    error.
//!
//! [`Ulid`]: ulid::Ulid
//! [`Uuid`]: uuid::Uuid

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]

use sqlx::migrate::Migrator;

pub mod app_session;
pub mod compat;
pub mod job;
pub mod oauth2;
pub mod upstream_oauth2;
pub mod user;

mod errors;
pub(crate) mod filter;
pub(crate) mod iden;
pub(crate) mod pagination;
pub(crate) mod repository;
pub(crate) mod tracing;

pub(crate) use self::errors::DatabaseInconsistencyError;
pub use self::{errors::DatabaseError, repository::PgRepository, tracing::ExecuteExt};

/// Embedded migrations, allowing them to run on startup
pub static MIGRATOR: Migrator = {
    // XXX: The macro does not let us ignore missing migrations, so we have to do it
    // like this. See https://github.com/launchbadge/sqlx/issues/1788
    let mut m = sqlx::migrate!();

    // We manually removed some migrations because they made us depend on the
    // `pgcrypto` extension. See: https://github.com/matrix-org/matrix-authentication-service/issues/1557
    m.ignore_missing = true;
    m
};
