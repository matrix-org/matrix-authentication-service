// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

//! Interactions with the database

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    clippy::future_not_send,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

use chrono::{DateTime, Utc};
use pagination::InvalidPagination;
use sqlx::{migrate::Migrator, postgres::PgQueryResult};
use thiserror::Error;
use ulid::Ulid;

trait LookupResultExt {
    type Output;

    /// Transform a [`Result`] from a sqlx query to transform "not found" errors
    /// into [`None`]
    fn to_option(self) -> Result<Option<Self::Output>, sqlx::Error>;
}

impl<T> LookupResultExt for Result<T, sqlx::Error> {
    type Output = T;

    fn to_option(self) -> Result<Option<Self::Output>, sqlx::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Generic error when interacting with the database
#[derive(Debug, Error)]
#[error(transparent)]
pub enum DatabaseError {
    /// An error which came from the database itself
    Driver(#[from] sqlx::Error),

    /// An error which occured while converting the data from the database
    Inconsistency(#[from] DatabaseInconsistencyError),

    /// An error which occured while generating the paginated query
    Pagination(#[from] InvalidPagination),

    /// An error which happened because the requested database operation is
    /// invalid
    #[error("Invalid database operation")]
    InvalidOperation {
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// An error which happens when an operation affects not enough or too many
    /// rows
    #[error("Expected {expected} rows to be affected, but {actual} rows were affected")]
    RowsAffected { expected: u64, actual: u64 },
}

impl DatabaseError {
    pub(crate) fn ensure_affected_rows(
        result: &PgQueryResult,
        expected: u64,
    ) -> Result<(), DatabaseError> {
        let actual = result.rows_affected();
        if actual == expected {
            Ok(())
        } else {
            Err(DatabaseError::RowsAffected { expected, actual })
        }
    }

    pub(crate) fn to_invalid_operation<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::InvalidOperation {
            source: Some(Box::new(e)),
        }
    }

    pub(crate) const fn invalid_operation() -> Self {
        Self::InvalidOperation { source: None }
    }
}

#[derive(Debug, Error)]
pub struct DatabaseInconsistencyError {
    table: &'static str,
    column: Option<&'static str>,
    row: Option<Ulid>,

    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for DatabaseInconsistencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Database inconsistency on table {}", self.table)?;
        if let Some(column) = self.column {
            write!(f, " column {column}")?;
        }
        if let Some(row) = self.row {
            write!(f, " row {row}")?;
        }

        Ok(())
    }
}

impl DatabaseInconsistencyError {
    #[must_use]
    pub(crate) const fn on(table: &'static str) -> Self {
        Self {
            table,
            column: None,
            row: None,
            source: None,
        }
    }

    #[must_use]
    pub(crate) const fn column(mut self, column: &'static str) -> Self {
        self.column = Some(column);
        self
    }

    #[must_use]
    pub(crate) const fn row(mut self, row: Ulid) -> Self {
        self.row = Some(row);
        self
    }

    pub(crate) fn source<E: std::error::Error + Send + Sync + 'static>(
        mut self,
        source: E,
    ) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Clock {
    _private: (),

    #[cfg(test)]
    mock: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
}

impl Clock {
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        #[cfg(test)]
        if let Some(timestamp) = &self.mock {
            let timestamp = timestamp.load(std::sync::atomic::Ordering::Relaxed);
            return chrono::TimeZone::timestamp_opt(&Utc, timestamp, 0).unwrap();
        }

        // This is the clock used elsewhere, it's fine to call Utc::now here
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }

    #[cfg(test)]
    pub fn mock() -> Self {
        use std::sync::{atomic::AtomicI64, Arc};

        use chrono::TimeZone;

        let datetime = Utc.with_ymd_and_hms(2022, 01, 16, 14, 40, 0).unwrap();
        let timestamp = datetime.timestamp();

        Self {
            mock: Some(Arc::new(AtomicI64::new(timestamp))),
            _private: (),
        }
    }

    #[cfg(test)]
    pub fn advance(&self, duration: chrono::Duration) {
        let timestamp = self
            .mock
            .as_ref()
            .expect("Clock::advance should only be called on mocked clocks in tests");
        timestamp.fetch_add(duration.num_seconds(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_mocked_clock() {
        let clock = Clock::mock();

        // Time should be frozen, and give out the same timestamp on each call
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_eq!(first, second);

        // Clock can be advanced by a fixed duration
        clock.advance(Duration::seconds(10));
        let third = clock.now();
        assert_eq!(first + Duration::seconds(10), third);
    }

    #[test]
    fn test_real_clock() {
        let clock = Clock::default();

        // Time should not be frozen
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_ne!(first, second);
        assert!(first < second);
    }
}

pub mod compat;
pub mod oauth2;
pub(crate) mod pagination;
pub(crate) mod repository;
pub(crate) mod tracing;
pub mod upstream_oauth2;
pub mod user;

pub use self::repository::{PgRepository, Repository};

/// Embedded migrations, allowing them to run on startup
pub static MIGRATOR: Migrator = sqlx::migrate!();
