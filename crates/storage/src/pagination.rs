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

use std::fmt::Write;

use sqlx::Arguments;
use ulid::Ulid;
use uuid::Uuid;

pub fn generate_pagination<'a, A, W>(
    query: &mut W,
    id_field: &'static str,
    arguments: &mut A,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(), anyhow::Error>
where
    W: Write,
    A: Arguments<'a>,
    Uuid: sqlx::Type<A::Database> + sqlx::Encode<'a, A::Database>,
    i64: sqlx::Type<A::Database> + sqlx::Encode<'a, A::Database>,
{
    // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
    // 1. Start from the greedy query: SELECT * FROM table

    // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
    // clause
    if let Some(after) = after {
        write!(query, " AND {id_field} > ")?;
        arguments.add(Uuid::from(after));
        arguments.format_placeholder(query)?;
    }

    // 3. If the before argument is provided, add `id < parsed_cursor` to the
    // `WHERE` clause
    if let Some(before) = before {
        write!(query, " AND {id_field} < ")?;
        arguments.add(Uuid::from(before));
        arguments.format_placeholder(query)?;
    }

    // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to
    // the query
    if let Some(count) = first {
        write!(query, " ORDER BY {id_field} ASC LIMIT ")?;
        arguments.add((count + 1) as i64);
        arguments.format_placeholder(query)?;
    // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1`
    // to the query
    } else if let Some(count) = last {
        write!(query, " ORDER BY ue.user_email_id DESC LIMIT ")?;
        arguments.add((count + 1) as i64);
        arguments.format_placeholder(query)?;
    } else {
        anyhow::bail!("Either 'first' or 'last' must be specified");
    }

    Ok(())
}

pub fn process_page<T>(
    mut page: Vec<T>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<T>), anyhow::Error> {
    let limit = match (first, last) {
        (Some(count), _) | (_, Some(count)) => count,
        _ => anyhow::bail!("Either 'first' or 'last' must be specified"),
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
