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

//! Database-related tasks

use std::str::FromStr;

use apalis::{
    cron::CronStream,
    prelude::{Data, Job, Monitor, TokioExecutor, WorkerBuilder, WorkerFactoryFn},
};
use chrono::{DateTime, Utc};
use mas_storage::{oauth2::OAuth2AccessTokenRepository, RepositoryAccess};
use tracing::{debug, info};

use crate::{
    utils::{metrics_layer, trace_layer, TracedJob},
    State,
};

#[derive(Default, Clone)]
pub struct CleanupExpiredTokensJob {
    scheduled: DateTime<Utc>,
}

impl From<DateTime<Utc>> for CleanupExpiredTokensJob {
    fn from(scheduled: DateTime<Utc>) -> Self {
        Self { scheduled }
    }
}

impl Job for CleanupExpiredTokensJob {
    const NAME: &'static str = "cleanup-expired-tokens";
}

impl TracedJob for CleanupExpiredTokensJob {}

pub async fn cleanup_expired_tokens(
    job: CleanupExpiredTokensJob,
    state: Data<State>,
) -> Result<(), mas_storage::RepositoryError> {
    debug!("cleanup expired tokens job scheduled at {}", job.scheduled);

    let clock = state.clock();
    let mut repo = state
        .repository()
        .await
        .map_err(mas_storage::RepositoryError::from_error)?;

    let count = repo.oauth2_access_token().cleanup_expired(&clock).await?;
    repo.save().await?;

    if count == 0 {
        debug!("no token to clean up");
    } else {
        info!(count, "cleaned up expired tokens");
    }

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
) -> Monitor<TokioExecutor> {
    let schedule = apalis::cron::Schedule::from_str("*/15 * * * * *").unwrap();
    let worker_name = format!("{job}-{suffix}", job = CleanupExpiredTokensJob::NAME);
    let worker = WorkerBuilder::new(worker_name)
        .data(state.clone())
        .layer(metrics_layer())
        .layer(trace_layer())
        .stream(CronStream::new(schedule).into_stream())
        .build_fn(cleanup_expired_tokens);

    monitor.register(worker)
}
