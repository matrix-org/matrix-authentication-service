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

use apalis_core::{executor::TokioExecutor, layers::extensions::Extension, monitor::Monitor};
use apalis_sql::postgres::PostgresStorage;
use mas_email::Mailer;
use mas_storage::{BoxClock, BoxRepository, Repository, SystemClock};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tracing::debug;

mod database;
mod email;
mod layers;

#[derive(Clone)]
struct State {
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
}

impl State {
    pub fn new(pool: Pool<Postgres>, clock: SystemClock, mailer: Mailer) -> Self {
        Self {
            pool,
            mailer,
            clock,
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

    pub fn rng(&self) -> rand_chacha::ChaChaRng {
        let _ = self;

        // This is fine.
        #[allow(clippy::disallowed_methods)]
        rand_chacha::ChaChaRng::from_rng(rand::thread_rng()).expect("failed to seed rng")
    }

    pub async fn repository(&self) -> Result<BoxRepository, DatabaseError> {
        let repo = PgRepository::from_pool(self.pool())
            .await?
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed();

        Ok(repo)
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
pub fn init(name: &str, pool: &Pool<Postgres>, mailer: &Mailer) -> Monitor<TokioExecutor> {
    let state = State::new(pool.clone(), SystemClock::default(), mailer.clone());
    let monitor = Monitor::new();
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state);
    debug!(?monitor, "workers registered");
    monitor
}
