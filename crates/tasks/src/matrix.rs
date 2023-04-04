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
    builder::{WorkerBuilder, WorkerFactory},
    context::JobContext,
    executor::TokioExecutor,
    job::Job,
    job_fn::job_fn,
    monitor::Monitor,
    storage::builder::WithStorage,
};
use mas_axum_utils::axum::{
    headers::{Authorization, HeaderMapExt},
    http::{Request, StatusCode},
};
use mas_http::HttpServiceExt;
use mas_storage::{
    job::{JobWithSpanContext, ProvisionUserJob},
    user::{UserEmailRepository, UserRepository},
    RepositoryAccess,
};
use serde::{Deserialize, Serialize};
use tower::{Service, ServiceExt};
use tracing::{info, info_span, Instrument};
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
        .http_client("provision-matrix-user")
        .await?
        .request_bytes_to_body()
        .json_request();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    let mxid = format!("@{}:{}", user.username, matrix.homeserver);

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

    let mut req = Request::put(
        matrix
            .endpoint
            .join("_synapse/admin/v2/users/")?
            .join(&mxid)?
            .as_str(),
    );
    req.headers_mut()
        .context("Failed to get headers")?
        .typed_insert(Authorization::bearer(&matrix.access_token)?);

    let req = req.body(body).context("Failed to build request")?;

    let span = info_span!("matrix.provision_user", %mxid);
    let response = client.ready().await?.call(req).instrument(span).await?;

    match response.status() {
        StatusCode::CREATED => info!(%user.id, %mxid, "User created"),
        StatusCode::OK => info!(%user.id, %mxid, "User updated"),
        // TODO: Better error handling
        code => anyhow::bail!("Failed to provision user. Status code: {code}"),
    }

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
) -> Monitor<TokioExecutor> {
    let storage = state.store();
    let worker_name = format!("{job}-{suffix}", job = ProvisionUserJob::NAME);
    let worker = WorkerBuilder::new(worker_name)
        .layer(state.inject())
        .layer(TracingLayer::new())
        .with_storage(storage)
        .build(job_fn(provision_user));
    monitor.register(worker)
}
