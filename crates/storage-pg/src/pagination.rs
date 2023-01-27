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

use mas_storage::{pagination::PaginationDirection, Pagination};
use sqlx::{Database, QueryBuilder};
use uuid::Uuid;

/// An extension trait to the `sqlx` [`QueryBuilder`], to help adding pagination
/// to a query
pub trait QueryBuilderExt {
    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination(&mut self, id_field: &'static str, pagination: Pagination) -> &mut Self;
}

impl<'a, DB> QueryBuilderExt for QueryBuilder<'a, DB>
where
    DB: Database,
    Uuid: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
    i64: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
{
    fn generate_pagination(&mut self, id_field: &'static str, pagination: Pagination) -> &mut Self {
        // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
        // 1. Start from the greedy query: SELECT * FROM table

        // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
        // clause
        if let Some(after) = pagination.after {
            self.push(" AND ")
                .push(id_field)
                .push(" > ")
                .push_bind(Uuid::from(after));
        }

        // 3. If the before argument is provided, add `id < parsed_cursor` to the
        // `WHERE` clause
        if let Some(before) = pagination.before {
            self.push(" AND ")
                .push(id_field)
                .push(" < ")
                .push_bind(Uuid::from(before));
        }

        match pagination.direction {
            // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to the
            // query
            PaginationDirection::Forward => {
                self.push(" ORDER BY ")
                    .push(id_field)
                    .push(" ASC LIMIT ")
                    .push_bind((pagination.count + 1) as i64);
            }
            // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1` to the
            // query
            PaginationDirection::Backward => {
                self.push(" ORDER BY ")
                    .push(id_field)
                    .push(" DESC LIMIT ")
                    .push_bind((pagination.count + 1) as i64);
            }
        };

        self
    }
}
