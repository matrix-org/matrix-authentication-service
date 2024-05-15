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
use mas_storage::{
    job::{JobRepository, JobSubmission},
    Clock,
};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;

use crate::{DatabaseError, ExecuteExt};

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
            job.name = submission.name(),
        ),
        err,
    )]
    async fn schedule_submission(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        submission: JobSubmission,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        // XXX: this is what apalis_core::job::JobId does
        let id = format!("JID-{id}");
        tracing::Span::current().record("job.id", &id);

        let res = sqlx::query!(
            r#"
                INSERT INTO apalis.jobs (job, id, job_type)
                VALUES ($1::json, $2::text, $3::text)
            "#,
            submission.payload(),
            id.to_string(),
            submission.name(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }
}
