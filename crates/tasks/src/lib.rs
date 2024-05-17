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

use apalis::prelude::{Monitor, TokioExecutor};
use apalis_core::layers::extensions::Data;
use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_storage::{BoxClock, BoxRepository, Repository, RepositoryError, SystemClock};
use mas_storage_pg::PgRepository;
use rand::SeedableRng;
use sqlx::{Pool, Postgres};

mod database;
mod email;
mod matrix;
mod user;
mod utils;

#[derive(Clone)]
struct State {
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
    homeserver: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
}

impl State {
    pub fn new(
        pool: Pool<Postgres>,
        clock: SystemClock,
        mailer: Mailer,
        homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
    ) -> Self {
        Self {
            pool,
            mailer,
            clock,
            homeserver: Arc::new(homeserver),
        }
    }

    pub fn inject(&self) -> Data<Self> {
        Data::new(self.clone())
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

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(self.pool())
            .await
            .map_err(mas_storage::RepositoryError::from_error)?
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed();

        Ok(repo)
    }

    pub fn matrix_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        self.homeserver.as_ref()
    }
}

/// Helper macro to build a storage-backed worker.
macro_rules! build {
    ($job:ty => $fn:ident, $suffix:expr, $state:expr, $pool:expr) => {{
        let storage = ::apalis_sql::postgres::PostgresStorage::new($pool.clone());
        let worker_name = format!(
            "{job}-{suffix}",
            job = <$job as ::apalis::prelude::Job>::NAME,
            suffix = $suffix
        );

        let builder = ::apalis::prelude::WorkerBuilder::new(worker_name)
            .layer($state.inject())
            .layer(crate::utils::trace_layer())
            .layer(crate::utils::metrics_layer())
            .with_storage(storage);
        ::apalis::prelude::WorkerFactoryFn::build_fn(builder, $fn)
    }};
}

pub(crate) use build;

/// Initialise the workers.
///
/// # Errors
///
/// This function can fail if the database connection fails.
pub fn init(
    name: &str,
    pool: &Pool<Postgres>,
    mailer: &Mailer,
    homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
) -> Monitor<TokioExecutor> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
    );
    let monitor = Monitor::<TokioExecutor>::new();
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state, pool);
    let monitor = self::matrix::register(name, monitor, &state, pool);
    let monitor = self::user::register(name, monitor, &state, pool);

    monitor.on_event(|e| {
        let event = e.inner();
        if let apalis::prelude::Event::Error(error) = e.inner() {
            tracing::error!(?error, "worker error");
        } else {
            tracing::debug!(?event, "worker event");
        }
    })
}
