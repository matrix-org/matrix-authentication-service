// Copyright 2023 The Matrix.org Foundation C.I.C.
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

//! A module containing the PostgreSQL implementation of the [`JobRepository`].

use async_trait::async_trait;
use mas_storage::job::{JobId, JobRepository, JobSubmission};
use sqlx::PgConnection;

use crate::{errors::DatabaseInconsistencyError, DatabaseError, ExecuteExt};

/// An implementation of [`JobRepository`] for a PostgreSQL connection.
pub struct PgJobRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgJobRepository<'c> {
    /// Create a new [`PgJobRepository`] from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl<'c> JobRepository for PgJobRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.job.schedule_submission",
        skip_all,
        fields(
            db.statement,
            job.id,
            job.name,
        ),
        err,
    )]
    async fn schedule_submission(
        &mut self,
        submission: JobSubmission,
    ) -> Result<JobId, Self::Error> {
        // XXX: The apalis.push_job function is not unique, so we have to specify all
        // the arguments
        let res = sqlx::query_scalar!(
            r#"
                SELECT id as "id!"
                FROM apalis.push_job($1::text, $2::json, 'Pending', now(), 25)
            "#,
            submission.name(),
            submission.payload(),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        let id = res
            .parse()
            .map_err(|source| DatabaseInconsistencyError::on("apalis.push_job").source(source))?;

        tracing::Span::current().record("job.id", tracing::field::display(&id));

        Ok(id)
    }
}
