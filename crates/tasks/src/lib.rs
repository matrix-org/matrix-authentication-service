// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use apalis_core::{executor::TokioExecutor, layers::extensions::Extension, monitor::Monitor};
use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, SystemClock};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tracing::debug;

use crate::storage::PostgresStorageFactory;

mod database;
mod email;
mod matrix;
mod recovery;
mod storage;
mod user;
mod utils;

#[derive(Clone)]
struct State {
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
    homeserver: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
    url_builder: UrlBuilder,
}

impl State {
    pub fn new(
        pool: Pool<Postgres>,
        clock: SystemClock,
        mailer: Mailer,
        homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
        url_builder: UrlBuilder,
    ) -> Self {
        Self {
            pool,
            mailer,
            clock,
            homeserver: Arc::new(homeserver),
            url_builder,
        }
    }

    pub fn inject(&self) -> Extension<Self> {
        Extension(self.clone())
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub fn clock(&self) -> BoxClock {
        Box::new(self.clock.clone())
    }

    pub fn mailer(&self) -> &Mailer {
        &self.mailer
    }

    // This is fine for now, we may move that to a trait at some point.
    #[allow(clippy::unused_self, clippy::disallowed_methods)]
    pub fn rng(&self) -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_rng(rand::thread_rng()).expect("failed to seed rng")
    }

    pub async fn repository(&self) -> Result<BoxRepository, DatabaseError> {
        let repo = PgRepository::from_pool(self.pool()).await?.boxed();

        Ok(repo)
    }

    pub fn matrix_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        self.homeserver.as_ref()
    }

    pub fn url_builder(&self) -> &UrlBuilder {
        &self.url_builder
    }
}

trait JobContextExt {
    fn state(&self) -> State;
}

impl JobContextExt for apalis_core::context::JobContext {
    fn state(&self) -> State {
        self.data_opt::<State>()
            .expect("state not injected in job context")
            .clone()
    }
}

/// Helper macro to build a storage-backed worker.
macro_rules! build {
    ($job:ty => $fn:ident, $suffix:expr, $state:expr, $factory:expr) => {{
        let storage = $factory.build();
        let worker_name = format!(
            "{job}-{suffix}",
            job = <$job as ::apalis_core::job::Job>::NAME,
            suffix = $suffix
        );

        let builder = ::apalis_core::builder::WorkerBuilder::new(worker_name)
            .layer($state.inject())
            .layer(crate::utils::trace_layer())
            .layer(crate::utils::metrics_layer());

        let builder = ::apalis_core::storage::builder::WithStorage::with_storage_config(
            builder,
            storage,
            |c| c.fetch_interval(std::time::Duration::from_secs(1)),
        );
        ::apalis_core::builder::WorkerFactory::build(builder, ::apalis_core::job_fn::job_fn($fn))
    }};
}

pub(crate) use build;

/// Initialise the workers.
///
/// # Errors
///
/// This function can fail if the database connection fails.
pub async fn init(
    name: &str,
    pool: &Pool<Postgres>,
    mailer: &Mailer,
    homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
    url_builder: UrlBuilder,
) -> Result<Monitor<TokioExecutor>, sqlx::Error> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        url_builder,
    );
    let factory = PostgresStorageFactory::new(pool.clone());
    let monitor = Monitor::new().executor(TokioExecutor::new());
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state, &factory);
    let monitor = self::matrix::register(name, monitor, &state, &factory);
    let monitor = self::user::register(name, monitor, &state, &factory);
    let monitor = self::recovery::register(name, monitor, &state, &factory);
    // TODO: we might want to grab the join handle here
    factory.listen().await?;
    debug!(?monitor, "workers registered");
    Ok(monitor)
}
