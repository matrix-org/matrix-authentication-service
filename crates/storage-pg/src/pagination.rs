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
use sea_query::IntoColumnRef;
use uuid::Uuid;

/// An extension trait to the `sqlx` [`QueryBuilder`], to help adding pagination
/// to a query
pub trait QueryBuilderExt {
    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination<C: IntoColumnRef>(
        &mut self,
        column: C,
        pagination: Pagination,
    ) -> &mut Self;
}

impl QueryBuilderExt for sea_query::SelectStatement {
    fn generate_pagination<C: IntoColumnRef>(
        &mut self,
        column: C,
        pagination: Pagination,
    ) -> &mut Self {
        let id_field = column.into_column_ref();

        // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
        // 1. Start from the greedy query: SELECT * FROM table

        // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
        // clause
        if let Some(after) = pagination.after {
            self.and_where(sea_query::Expr::col(id_field.clone()).gt(Uuid::from(after)));
        }

        // 3. If the before argument is provided, add `id < parsed_cursor` to the
        // `WHERE` clause
        if let Some(before) = pagination.before {
            self.and_where(sea_query::Expr::col(id_field.clone()).lt(Uuid::from(before)));
        }

        match pagination.direction {
            // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to the
            // query
            PaginationDirection::Forward => {
                self.order_by(id_field, sea_query::Order::Asc)
                    .limit((pagination.count + 1) as u64);
            }
            // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1` to the
            // query
            PaginationDirection::Backward => {
                self.order_by(id_field, sea_query::Order::Desc)
                    .limit((pagination.count + 1) as u64);
            }
        };

        self
    }
}
