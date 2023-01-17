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

//! Utilities to manage paginated queries.

use sqlx::{Database, QueryBuilder};
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

/// An error returned when invalid pagination parameters are provided
#[derive(Debug, Error)]
#[error("Either 'first' or 'last' must be specified")]
pub struct InvalidPagination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    before: Option<Ulid>,
    after: Option<Ulid>,
    count: usize,
    direction: PaginationDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaginationDirection {
    Forward,
    Backward,
}

impl Pagination {
    /// Creates a new [`Pagination`] from user-provided parameters.
    ///
    /// # Errors
    ///
    /// Either `first` or `last` must be provided, else this function will
    /// return an [`InvalidPagination`] error.
    pub const fn try_new(
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Self, InvalidPagination> {
        let (direction, count) = match (first, last) {
            (Some(first), _) => (PaginationDirection::Forward, first),
            (_, Some(last)) => (PaginationDirection::Backward, last),
            (None, None) => return Err(InvalidPagination),
        };

        Ok(Self {
            before,
            after,
            count,
            direction,
        })
    }

    /// Creates a [`Pagination`] which gets the first N items
    pub const fn first(first: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: first,
            direction: PaginationDirection::Forward,
        }
    }

    /// Creates a [`Pagination`] which gets the last N items
    pub const fn last(last: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: last,
            direction: PaginationDirection::Backward,
        }
    }

    /// Get items before the given cursor
    pub const fn before(mut self, id: Ulid) -> Self {
        self.before = Some(id);
        self
    }

    /// Get items after the given cursor
    pub const fn after(mut self, id: Ulid) -> Self {
        self.after = Some(id);
        self
    }

    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination<'a, DB>(&self, query: &mut QueryBuilder<'a, DB>, id_field: &'static str)
    where
        DB: Database,
        Uuid: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
        i64: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
    {
        // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
        // 1. Start from the greedy query: SELECT * FROM table

        // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
        // clause
        if let Some(after) = self.after {
            query
                .push(" AND ")
                .push(id_field)
                .push(" > ")
                .push_bind(Uuid::from(after));
        }

        // 3. If the before argument is provided, add `id < parsed_cursor` to the
        // `WHERE` clause
        if let Some(before) = self.before {
            query
                .push(" AND ")
                .push(id_field)
                .push(" < ")
                .push_bind(Uuid::from(before));
        }

        match self.direction {
            // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to the
            // query
            PaginationDirection::Forward => {
                query
                    .push(" ORDER BY ")
                    .push(id_field)
                    .push(" ASC LIMIT ")
                    .push_bind((self.count + 1) as i64);
            }
            // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1` to the
            // query
            PaginationDirection::Backward => {
                query
                    .push(" ORDER BY ")
                    .push(id_field)
                    .push(" DESC LIMIT ")
                    .push_bind((self.count + 1) as i64);
            }
        };
    }

    /// Process a page returned by a paginated query
    pub fn process<T>(&self, mut edges: Vec<T>) -> Page<T> {
        let is_full = edges.len() == (self.count + 1);
        if is_full {
            edges.pop();
        }

        let (has_previous_page, has_next_page) = match self.direction {
            PaginationDirection::Forward => (false, is_full),
            PaginationDirection::Backward => {
                // 6. If the last argument is provided, I reverse the order of the results
                edges.reverse();
                (is_full, false)
            }
        };

        Page {
            has_next_page,
            has_previous_page,
            edges,
        }
    }
}

pub struct Page<T> {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub edges: Vec<T>,
}

impl<T> Page<T> {
    pub fn map<F, T2>(self, f: F) -> Page<T2>
    where
        F: FnMut(T) -> T2,
    {
        let edges = self.edges.into_iter().map(f).collect();
        Page {
            has_next_page: self.has_next_page,
            has_previous_page: self.has_previous_page,
            edges,
        }
    }

    pub fn try_map<F, E, T2>(self, f: F) -> Result<Page<T2>, E>
    where
        F: FnMut(T) -> Result<T2, E>,
    {
        let edges: Result<Vec<T2>, E> = self.edges.into_iter().map(f).collect();
        Ok(Page {
            has_next_page: self.has_next_page,
            has_previous_page: self.has_previous_page,
            edges: edges?,
        })
    }
}

/// An extension trait to the `sqlx` [`QueryBuilder`], to help adding pagination
/// to a query
pub trait QueryBuilderExt {
    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination(&mut self, id_field: &'static str, pagination: &Pagination)
        -> &mut Self;
}

impl<'a, DB> QueryBuilderExt for QueryBuilder<'a, DB>
where
    DB: Database,
    Uuid: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
    i64: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
{
    fn generate_pagination(
        &mut self,
        id_field: &'static str,
        pagination: &Pagination,
    ) -> &mut Self {
        pagination.generate_pagination(self, id_field);
        self
    }
}
