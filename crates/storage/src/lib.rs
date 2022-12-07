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

#[derive(Debug, Error)]
#[error("failed to lookup {what}")]
pub struct GenericLookupError {
    what: &'static str,
    source: sqlx::Error,
}

impl GenericLookupError {
    #[must_use]
    pub fn what(what: &'static str) -> Box<dyn Fn(sqlx::Error) -> Self> {
        Box::new(move |source: sqlx::Error| Self { what, source })
    }
}

impl LookupError for GenericLookupError {
    fn not_found(&self) -> bool {
        matches!(self.source, sqlx::Error::RowNotFound)
    }
}

impl LookupError for sqlx::Error {
    fn not_found(&self) -> bool {
        matches!(self, sqlx::Error::RowNotFound)
    }
}

pub trait LookupError {
    fn not_found(&self) -> bool;
}

pub trait LookupResultExt {
    type Error;
    type Output;

    /// Transform a [`Result`] with a [`LookupError`] to transform "not
    /// found" errors into [`None`]
    fn to_option(self) -> Result<Option<Self::Output>, Self::Error>;
}

impl<T, E> LookupResultExt for Result<T, E>
where
    E: LookupError,
{
    type Output = T;
    type Error = E;
    fn to_option(self) -> Result<Option<Self::Output>, Self::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.not_found() => Ok(None),
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
    Inconsistency(#[from] DatabaseInconsistencyError2),

    /// An error which occured while generating the paginated query
    Pagination(#[from] InvalidPagination),

    /// An error which happened because the requested database operation is
    /// invalid
    #[error("Invalid database operation")]
    InvalidOperation,

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
}

#[derive(Debug, Error)]
pub struct DatabaseInconsistencyError2 {
    table: &'static str,
    column: Option<&'static str>,
    row: Option<Ulid>,

    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for DatabaseInconsistencyError2 {
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

impl DatabaseInconsistencyError2 {
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

#[derive(Default, Debug, Clone, Copy)]
pub struct Clock {
    _private: (),
}

impl Clock {
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        // This is the clock used elsewhere, it's fine to call Utc::now here
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }
}

#[derive(Debug, Error)]
#[error("database query returned an inconsistent state")]
pub struct DatabaseInconsistencyError;

pub mod compat;
pub mod oauth2;
pub(crate) mod pagination;
pub mod upstream_oauth2;
pub mod user;

/// Embedded migrations, allowing them to run on startup
pub static MIGRATOR: Migrator = sqlx::migrate!();
