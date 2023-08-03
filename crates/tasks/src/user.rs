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

use std::time::Duration;

use anyhow::Context;
use apalis_core::{
    builder::{WorkerBuilder, WorkerFactoryFn},
    context::JobContext,
    executor::TokioExecutor,
    job::Job,
    monitor::Monitor,
    storage::builder::WithStorage,
};
use mas_storage::{
    job::{DeactivateUserJob, DeleteDeviceJob, JobWithSpanContext},
    user::UserRepository,
    RepositoryAccess,
};
use tracing::info;

use crate::{
    storage::PostgresStorageFactory,
    utils::{metrics_layer, trace_layer},
    JobContextExt, State,
};

/// Job to deactivate a user, both locally and on the Matrix homeserver.
#[tracing::instrument(
    name = "job.deactivate_user"
    fields(user.id = %job.user_id(), erase = %job.hs_erase()),
    skip_all,
    err(Debug),
)]
async fn deactivate_user(
    job: JobWithSpanContext<DeactivateUserJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let clock = state.clock();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // Let's first lock the user
    let user = repo
        .user()
        .lock(&clock, user)
        .await
        .context("Failed to lock user")?;

    // TODO: delete the sessions & access tokens

    // Before calling back to the homeserver, commit the changes to the database
    repo.save().await?;

    let mxid = matrix.mxid(&user.username);
    info!("Deactivating user {} on homeserver", mxid);
    matrix.delete_user(&mxid, job.hs_erase()).await?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let storage = storage_factory.build();
    let worker_name = format!("{job}-{suffix}", job = DeleteDeviceJob::NAME);
    let deactivate_user_worker = WorkerBuilder::new(worker_name)
        .layer(state.inject())
        .layer(trace_layer())
        .layer(metrics_layer())
        .with_storage_config(storage, |c| c.fetch_interval(Duration::from_secs(1)))
        .build_fn(deactivate_user);

    monitor.register(deactivate_user_worker)
}
