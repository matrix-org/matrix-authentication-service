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

use anyhow::Context;
use apalis::prelude::{JobContext, Monitor, TokioExecutor};
use mas_matrix::ProvisionRequest;
use mas_storage::{
    job::{DeleteDeviceJob, JobWithSpanContext, ProvisionDeviceJob, ProvisionUserJob},
    user::{UserEmailRepository, UserRepository},
    RepositoryAccess,
};
use tracing::info;

use crate::{storage::PostgresStorageFactory, JobContextExt, State};

/// Job to provision a user on the Matrix homeserver.
/// This works by doing a PUT request to the /_synapse/admin/v2/users/{user_id}
/// endpoint.
#[tracing::instrument(
    name = "job.provision_user"
    fields(user.id = %job.user_id()),
    skip_all,
    err(Debug),
)]
async fn provision_user(
    job: JobWithSpanContext<ProvisionUserJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    let mxid = matrix.mxid(&user.username);
    let emails = repo
        .user_email()
        .all(&user)
        .await?
        .into_iter()
        .filter(|email| email.confirmed_at.is_some())
        .map(|email| email.email)
        .collect();

    repo.cancel().await?;

    let mut request = ProvisionRequest::new(mxid.clone(), user.sub.clone()).set_emails(emails);

    if let Some(display_name) = job.display_name_to_set() {
        request = request.set_displayname(display_name.to_owned());
    }

    let created = matrix.provision_user(&request).await?;

    if created {
        info!(%user.id, %mxid, "User created");
    } else {
        info!(%user.id, %mxid, "User updated");
    }

    Ok(())
}

/// Job to provision a device on the Matrix homeserver.
/// This works by doing a POST request to the
/// /_synapse/admin/v2/users/{user_id}/devices endpoint.
#[tracing::instrument(
    name = "job.provision_device"
    fields(
        user.id = %job.user_id(),
        device.id = %job.device_id(),
    ),
    skip_all,
    err(Debug),
)]
async fn provision_device(
    job: JobWithSpanContext<ProvisionDeviceJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    let mxid = matrix.mxid(&user.username);

    matrix.create_device(&mxid, job.device_id()).await?;
    info!(%user.id, %mxid, device.id = job.device_id(), "Device created");

    Ok(())
}

/// Job to delete a device from a user's account.
/// This works by doing a DELETE request to the
/// /_synapse/admin/v2/users/{user_id}/devices/{device_id} endpoint.
#[tracing::instrument(
    name = "job.delete_device"
    fields(
        user.id = %job.user_id(),
        device.id = %job.device_id(),
    ),
    skip_all,
    err(Debug),
)]
async fn delete_device(
    job: JobWithSpanContext<DeleteDeviceJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    let mxid = matrix.mxid(&user.username);

    matrix.delete_device(&mxid, job.device_id()).await?;
    info!(%user.id, %mxid, device.id = job.device_id(), "Device deleted");

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let provision_user_worker =
        crate::build!(ProvisionUserJob => provision_user, suffix, state, storage_factory);
    let provision_device_worker =
        crate::build!(ProvisionDeviceJob => provision_device, suffix, state, storage_factory);
    let delete_device_worker =
        crate::build!(DeleteDeviceJob => delete_device, suffix, state, storage_factory);

    monitor
        .register(provision_user_worker)
        .register(provision_device_worker)
        .register(delete_device_worker)
}
