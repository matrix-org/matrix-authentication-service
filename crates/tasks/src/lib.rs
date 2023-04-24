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

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::str_to_string, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]

use std::sync::Arc;

use apalis_core::{executor::TokioExecutor, layers::extensions::Extension, monitor::Monitor};
use apalis_sql::postgres::PostgresStorage;
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_email::Mailer;
use mas_http::{ClientInitError, ClientService, TracedClient};
use mas_storage::{BoxClock, BoxRepository, Repository, SystemClock};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tracing::debug;

mod database;
mod email;
mod matrix;
mod utils;

pub use self::matrix::HomeserverConnection;

#[derive(Clone)]
struct State {
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
    homeserver: Arc<HomeserverConnection>,
    http_client_factory: HttpClientFactory,
}

impl State {
    pub fn new(
        pool: Pool<Postgres>,
        clock: SystemClock,
        mailer: Mailer,
        homeserver: HomeserverConnection,
        http_client_factory: HttpClientFactory,
    ) -> Self {
        Self {
            pool,
            mailer,
            clock,
            homeserver: Arc::new(homeserver),
            http_client_factory,
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

    pub fn store<J>(&self) -> PostgresStorage<J> {
        PostgresStorage::new(self.pool.clone())
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
        let repo = PgRepository::from_pool(self.pool())
            .await?
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed();

        Ok(repo)
    }

    pub fn matrix_connection(&self) -> &HomeserverConnection {
        &self.homeserver
    }

    pub async fn http_client<B>(&self) -> Result<ClientService<TracedClient<B>>, ClientInitError>
    where
        B: mas_axum_utils::axum::body::HttpBody + Send,
        B::Data: Send,
    {
        self.http_client_factory.client().await
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

#[must_use]
pub fn init(
    name: &str,
    pool: &Pool<Postgres>,
    mailer: &Mailer,
    homeserver: HomeserverConnection,
    http_client_factory: &HttpClientFactory,
) -> Monitor<TokioExecutor> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        http_client_factory.clone(),
    );
    let monitor = Monitor::new().executor(TokioExecutor::new());
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state);
    let monitor = self::matrix::register(name, monitor, &state);
    debug!(?monitor, "workers registered");
    monitor
}
