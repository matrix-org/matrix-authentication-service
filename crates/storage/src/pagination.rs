// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use sqlx::{Database, QueryBuilder};
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

#[derive(Debug, Error)]
#[error("Either 'first' or 'last' must be specified")]
pub struct InvalidPagination;

/// Add cursor-based pagination to a query, as used in paginated GraphQL
/// connections
pub fn generate_pagination<'a, DB>(
    query: &mut QueryBuilder<'a, DB>,
    id_field: &'static str,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(), InvalidPagination>
where
    DB: Database,
    Uuid: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
    i64: sqlx::Type<DB> + sqlx::Encode<'a, DB>,
{
    // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
    // 1. Start from the greedy query: SELECT * FROM table

    // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
    // clause
    if let Some(after) = after {
        query
            .push(" AND ")
            .push(id_field)
            .push(" > ")
            .push_bind(Uuid::from(after));
    }

    // 3. If the before argument is provided, add `id < parsed_cursor` to the
    // `WHERE` clause
    if let Some(before) = before {
        query
            .push(" AND ")
            .push(id_field)
            .push(" < ")
            .push_bind(Uuid::from(before));
    }

    // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to
    // the query
    if let Some(count) = first {
        query
            .push(" ORDER BY ")
            .push(id_field)
            .push(" ASC LIMIT ")
            .push_bind((count + 1) as i64);
    // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1`
    // to the query
    } else if let Some(count) = last {
        query
            .push(" ORDER BY ")
            .push(id_field)
            .push(" DESC LIMIT ")
            .push_bind((count + 1) as i64);
    } else {
        return Err(InvalidPagination);
    }

    Ok(())
}

/// Process a page returned by a paginated query
pub fn process_page<T>(
    mut page: Vec<T>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<T>), InvalidPagination> {
    let limit = match (first, last) {
        (Some(count), _) | (_, Some(count)) => count,
        _ => return Err(InvalidPagination),
    };

    let is_full = page.len() == (limit + 1);
    if is_full {
        page.pop();
    }

    let (has_previous_page, has_next_page) = if first.is_some() {
        (false, is_full)
    } else if last.is_some() {
        // 6. If the last argument is provided, I reverse the order of the results
        page.reverse();
        (is_full, false)
    } else {
        unreachable!()
    };

    Ok((has_previous_page, has_next_page, page))
}

pub trait QueryBuilderExt {
    fn generate_pagination(
        &mut self,
        id_field: &'static str,
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<&mut Self, anyhow::Error>;
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
        before: Option<Ulid>,
        after: Option<Ulid>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<&mut Self, anyhow::Error> {
        generate_pagination(self, id_field, before, after, first, last)?;
        Ok(self)
    }
}
