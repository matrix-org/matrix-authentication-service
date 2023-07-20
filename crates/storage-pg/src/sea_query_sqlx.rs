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

//! A [`sea_query::Values`] to [`sqlx::Arguments`] mapper

use sea_query::Value;
use sqlx::Arguments;

pub(crate) fn map_values(values: sea_query::Values) -> sqlx::postgres::PgArguments {
    let mut arguments = sqlx::postgres::PgArguments::default();

    for value in values {
        match value {
            Value::Bool(b) => arguments.add(b),
            Value::TinyInt(i) => arguments.add(i),
            Value::SmallInt(i) => arguments.add(i),
            Value::Int(i) => arguments.add(i),
            Value::BigInt(i) => arguments.add(i),
            Value::TinyUnsigned(u) => arguments.add(u.map(i16::from)),
            Value::SmallUnsigned(u) => arguments.add(u.map(i32::from)),
            Value::Unsigned(u) => arguments.add(u.map(i64::from)),
            Value::BigUnsigned(u) => arguments.add(u.map(|u| i64::try_from(u).unwrap_or(i64::MAX))),
            Value::Float(f) => arguments.add(f),
            Value::Double(d) => arguments.add(d),
            Value::String(s) => arguments.add(s.as_deref()),
            Value::Char(c) => arguments.add(c.map(|c| c.to_string())),
            Value::Bytes(b) => arguments.add(b.as_deref()),
            Value::ChronoDate(d) => arguments.add(d.as_deref()),
            Value::ChronoTime(t) => arguments.add(t.as_deref()),
            Value::ChronoDateTime(dt) => arguments.add(dt.as_deref()),
            Value::ChronoDateTimeUtc(dt) => arguments.add(dt.as_deref()),
            Value::ChronoDateTimeLocal(dt) => arguments.add(dt.as_deref()),
            Value::ChronoDateTimeWithTimeZone(dt) => arguments.add(dt.as_deref()),
            Value::Uuid(u) => arguments.add(u.as_deref()),

            // This depends on the features enabled for sea-query, so let's keep the wildcard
            #[allow(unreachable_patterns)]
            _ => unimplemented!(),
        }
    }

    arguments
}
