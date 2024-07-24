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

use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use tracing::Span;

/// An extension trait for [`sqlx::Execute`] that records the SQL statement as
/// `db.query.text` in a tracing span
pub trait ExecuteExt<'q, DB>: Sized {
    /// Records the statement as `db.query.text` in the current span
    #[must_use]
    fn traced(self) -> Self {
        self.record(&Span::current())
    }

    /// Records the statement as `db.query.text` in the given span
    #[must_use]
    fn record(self, span: &Span) -> Self;
}

impl<'q, DB, T> ExecuteExt<'q, DB> for T
where
    T: sqlx::Execute<'q, DB>,
    DB: sqlx::Database,
{
    fn record(self, span: &Span) -> Self {
        span.record(DB_QUERY_TEXT, self.sql());
        self
    }
}
