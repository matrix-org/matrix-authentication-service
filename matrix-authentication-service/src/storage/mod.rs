// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::collections::HashMap;

use sqlx::migrate::Migrator;

mod client;
// mod session;
mod user;

pub use self::{
    client::{Client, ClientLookupError, InvalidRedirectUriError},
    user::User,
};

pub static MIGRATOR: Migrator = sqlx::migrate!();

#[derive(Debug)]
pub struct Storage<Pool> {
    pool: Pool,
    clients: HashMap<String, Client>,
}

impl<Pool> Storage<Pool> {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            clients: HashMap::default(),
        }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }
}
