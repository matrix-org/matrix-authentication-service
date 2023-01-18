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

use thiserror::Error;
use ulid::Ulid;

/// An error returned when invalid pagination parameters are provided
#[derive(Debug, Error)]
#[error("Either 'first' or 'last' must be specified")]
pub struct InvalidPagination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    pub before: Option<Ulid>,
    pub after: Option<Ulid>,
    pub count: usize,
    pub direction: PaginationDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationDirection {
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
    #[must_use]
    pub const fn first(first: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: first,
            direction: PaginationDirection::Forward,
        }
    }

    /// Creates a [`Pagination`] which gets the last N items
    #[must_use]
    pub const fn last(last: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: last,
            direction: PaginationDirection::Backward,
        }
    }

    /// Get items before the given cursor
    #[must_use]
    pub const fn before(mut self, id: Ulid) -> Self {
        self.before = Some(id);
        self
    }

    /// Get items after the given cursor
    #[must_use]
    pub const fn after(mut self, id: Ulid) -> Self {
        self.after = Some(id);
        self
    }

    /// Process a page returned by a paginated query
    #[must_use]
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
    #[must_use]
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
