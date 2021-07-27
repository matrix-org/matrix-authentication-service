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

use std::sync::Arc;

use sqlx::PgPool;
use tera::Tera;

use crate::{config::RootConfig, storage::Storage};

#[derive(Clone)]
pub struct State {
    config: Arc<RootConfig>,
    templates: Arc<Tera>,
    storage: Arc<Storage<PgPool>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish()
    }
}

impl State {
    pub fn new(config: RootConfig, templates: Tera, storage: Storage<PgPool>) -> Self {
        Self {
            config: Arc::new(config),
            templates: Arc::new(templates),
            storage: Arc::new(storage),
        }
    }

    pub fn config(&self) -> &RootConfig {
        &self.config
    }

    pub fn storage(&self) -> &Storage<PgPool> {
        &self.storage
    }

    pub fn templates(&self) -> &Tera {
        &self.templates
    }
}
