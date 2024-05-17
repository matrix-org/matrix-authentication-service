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

use apalis::prelude::{Monitor, TokioExecutor};
use apalis_core::layers::extensions::Data;
use mas_storage::{
    job::{DeactivateUserJob, JobWithSpanContext},
    user::UserRepository,
    RepositoryAccess,
};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

use crate::State;

#[derive(Debug, Error)]
pub enum Error {
    #[error("User not found: {0}")]
    UserNotFound(Ulid),

    #[error("Failed to do homesever operation")]
    HomeserverConnection(#[source] anyhow::Error),

    #[error("Repository error")]
    Repository(#[from] mas_storage::RepositoryError),
}

/// Job to deactivate a user, both locally and on the Matrix homeserver.
#[tracing::instrument(
    name = "job.deactivate_user"
    fields(user.id = %job.user_id(), erase = %job.hs_erase()),
    skip_all,
    err(Debug),
)]
async fn deactivate_user(
    job: JobWithSpanContext<DeactivateUserJob>,
    state: Data<State>,
) -> Result<(), Error> {
    let clock = state.clock();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .ok_or(Error::UserNotFound(job.user_id()))?;

    // Let's first lock the user
    let user = repo.user().lock(&clock, user).await?;

    // TODO: delete the sessions & access tokens

    // Before calling back to the homeserver, commit the changes to the database
    repo.save().await?;

    let mxid = matrix.mxid(&user.username);
    info!("Deactivating user {} on homeserver", mxid);
    matrix
        .delete_user(&mxid, job.hs_erase())
        .await
        .map_err(Error::HomeserverConnection)?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    pool: &PgPool,
) -> Monitor<TokioExecutor> {
    let deactivate_user_worker =
        crate::build!(DeactivateUserJob => deactivate_user, suffix, state, pool);

    monitor.register(deactivate_user_worker)
}
