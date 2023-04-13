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
use apalis_core::{
    builder::{WorkerBuilder, WorkerFactory, WorkerFactoryFn},
    context::JobContext,
    executor::TokioExecutor,
    job::Job,
    monitor::Monitor,
    storage::builder::WithStorage,
};
use mas_axum_utils::axum::{
    headers::{Authorization, HeaderMapExt},
    http::{Request, StatusCode},
};
use mas_http::{EmptyBody, HttpServiceExt};
use mas_storage::{
    job::{DeleteDeviceJob, JobWithSpanContext, ProvisionDeviceJob, ProvisionUserJob},
    user::{UserEmailRepository, UserRepository},
    RepositoryAccess,
};
use serde::{Deserialize, Serialize};
use tower::{Service, ServiceExt};
use tracing::info;
use url::Url;

use crate::{layers::TracingLayer, JobContextExt, State};

pub struct HomeserverConnection {
    homeserver: String,
    endpoint: Url,
    access_token: String,
}

impl HomeserverConnection {
    pub fn new(homeserver: String, endpoint: Url, access_token: String) -> Self {
        Self {
            homeserver,
            endpoint,
            access_token,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ExternalID {
    pub auth_provider: String,
    pub external_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ThreePIDMedium {
    Email,
    MSISDN,
}

#[derive(Serialize, Deserialize)]
struct ThreePID {
    pub medium: ThreePIDMedium,
    pub address: String,
}

#[derive(Serialize, Deserialize)]
struct UserRequest {
    #[serde(rename = "displayname")]
    pub display_name: String,

    #[serde(rename = "threepids")]
    pub three_pids: Vec<ThreePID>,

    pub external_ids: Vec<ExternalID>,
}

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
    let mut client = state
        .http_client("matrix.provision_user")
        .await?
        .request_bytes_to_body()
        .json_request();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // XXX: there is a lot that could go wrong in terms of encoding here
    let mxid = format!(
        "@{localpart}:{homeserver}",
        localpart = user.username,
        homeserver = matrix.homeserver
    );

    let three_pids = repo
        .user_email()
        .all(&user)
        .await?
        .into_iter()
        .filter_map(|email| {
            if email.confirmed_at.is_some() {
                Some(ThreePID {
                    medium: ThreePIDMedium::Email,
                    address: email.email,
                })
            } else {
                None
            }
        })
        .collect();

    let display_name = user.username.clone();

    let body = UserRequest {
        display_name,
        three_pids,
        external_ids: vec![ExternalID {
            auth_provider: "oauth-delegated".to_string(),
            external_id: user.sub,
        }],
    };

    repo.cancel().await?;

    let path = format!("_synapse/admin/v2/users/{user_id}", user_id = mxid,);
    let mut req = Request::put(matrix.endpoint.join(&path)?.as_str());
    req.headers_mut()
        .context("Failed to get headers")?
        .typed_insert(Authorization::bearer(&matrix.access_token)?);

    let req = req.body(body).context("Failed to build request")?;

    let response = client.ready().await?.call(req).await?;

    match response.status() {
        StatusCode::CREATED => info!(%user.id, %mxid, "User created"),
        StatusCode::OK => info!(%user.id, %mxid, "User updated"),
        // TODO: Better error handling
        code => anyhow::bail!("Failed to provision user. Status code: {code}"),
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct DeviceRequest {
    device_id: String,
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
    let mut client = state
        .http_client("matrix.provision_device")
        .await?
        .request_bytes_to_body()
        .json_request();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // XXX: there is a lot that could go wrong in terms of encoding here
    let mxid = format!(
        "@{localpart}:{homeserver}",
        localpart = user.username,
        homeserver = matrix.homeserver
    );

    let path = format!("_synapse/admin/v2/users/{user_id}/devices", user_id = mxid);
    let mut req = Request::post(matrix.endpoint.join(&path)?.as_str());
    req.headers_mut()
        .context("Failed to get headers")?
        .typed_insert(Authorization::bearer(&matrix.access_token)?);

    let req = req
        .body(DeviceRequest {
            device_id: job.device_id().to_owned(),
        })
        .context("Failed to build request")?;

    let response = client.ready().await?.call(req).await?;

    match response.status() {
        StatusCode::CREATED => {
            info!(%user.id, %mxid, device.id = job.device_id(), "Device created")
        }
        code => anyhow::bail!("Failed to provision device. Status code: {code}"),
    }

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
    let mut client = state.http_client("matrix.delete_device").await?;
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // XXX: there is a lot that could go wrong in terms of encoding here
    let mxid = format!(
        "@{localpart}:{homeserver}",
        localpart = user.username,
        homeserver = matrix.homeserver
    );

    let path = format!(
        "_synapse/admin/v2/users/{mxid}/devices/{device_id}",
        device_id = job.device_id()
    );

    let mut req = Request::delete(matrix.endpoint.join(&path)?.as_str());
    req.headers_mut()
        .context("Failed to get headers")?
        .typed_insert(Authorization::bearer(&matrix.access_token)?);
    let req = req
        .body(EmptyBody::new())
        .context("Failed to build request")?;

    let response = client.ready().await?.call(req).await?;

    match response.status() {
        StatusCode::OK => info!(%user.id, %mxid, "Device deleted"),
        code => anyhow::bail!("Failed to delete device. Status code: {code}"),
    };

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
) -> Monitor<TokioExecutor> {
    let storage = state.store();
    let worker_name = format!("{job}-{suffix}", job = ProvisionUserJob::NAME);
    let provision_user_worker = WorkerBuilder::new(worker_name)
        .layer(state.inject())
        .layer(TracingLayer::new())
        .with_storage(storage)
        .build_fn(provision_user);

    let storage = state.store();
    let worker_name = format!("{job}-{suffix}", job = ProvisionDeviceJob::NAME);
    let provision_device_worker = WorkerBuilder::new(worker_name)
        .layer(state.inject())
        .layer(TracingLayer::new())
        .with_storage(storage)
        .build_fn(provision_device);

    let storage = state.store();
    let worker_name = format!("{job}-{suffix}", job = DeleteDeviceJob::NAME);
    let delete_device_worker = WorkerBuilder::new(worker_name)
        .layer(state.inject())
        .layer(TracingLayer::new())
        .with_storage(storage)
        .build_fn(delete_device);

    monitor
        .register(provision_user_worker)
        .register(provision_device_worker)
        .register(delete_device_worker)
}
