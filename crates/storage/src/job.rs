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

//! Repository to schedule persistent jobs.

pub use apalis_core::job::{Job, JobId};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::repository_impl;

/// A job submission to be scheduled through the repository.
pub struct JobSubmission {
    name: &'static str,
    payload: Value,
}

impl JobSubmission {
    /// Create a new job submission out of a [`Job`].
    ///
    /// # Panics
    ///
    /// Panics if the job cannot be serialized.
    #[must_use]
    pub fn new<J: Job + Serialize>(job: J) -> Self {
        Self {
            name: J::NAME,
            payload: serde_json::to_value(job).expect("failed to serialize job"),
        }
    }

    /// The name of the job.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The payload of the job.
    #[must_use]
    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

/// A [`JobRepository`] is used to schedule jobs to be executed by a worker.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job submission to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `submission` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_submission(
        &mut self,
        submission: JobSubmission,
    ) -> Result<JobId, Self::Error>;
}

repository_impl!(JobRepository:
    async fn schedule_submission(&mut self, submission: JobSubmission) -> Result<JobId, Self::Error>;
);

/// An extension trait for [`JobRepository`] to schedule jobs directly.
#[async_trait]
pub trait JobRepositoryExt {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `job` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_job<J: Job + Serialize>(&mut self, job: J) -> Result<JobId, Self::Error>;
}

#[async_trait]
impl<T> JobRepositoryExt for T
where
    T: JobRepository + ?Sized,
{
    type Error = T::Error;

    async fn schedule_job<J: Job + Serialize>(&mut self, job: J) -> Result<JobId, Self::Error> {
        self.schedule_submission(JobSubmission::new(job)).await
    }
}

mod jobs {
    // XXX: Move this somewhere else?
    use apalis_core::job::Job;
    use mas_data_model::UserEmail;
    use serde::{Deserialize, Serialize};
    use ulid::Ulid;

    /// A job to verify an email address.
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct VerifyEmailJob {
        user_email_id: Ulid,
    }

    impl VerifyEmailJob {
        /// Create a new job to verify an email address.
        #[must_use]
        pub fn new(user_email: &UserEmail) -> Self {
            Self {
                user_email_id: user_email.id,
            }
        }

        /// The ID of the email address to verify.
        #[must_use]
        pub fn user_email_id(&self) -> Ulid {
            self.user_email_id
        }
    }

    impl Job for VerifyEmailJob {
        const NAME: &'static str = "verify-email";
    }
}

pub use self::jobs::VerifyEmailJob;
