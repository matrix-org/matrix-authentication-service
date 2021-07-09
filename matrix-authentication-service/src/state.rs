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

use async_trait::async_trait;
use sqlx::PgPool;
use tera::Tera;
use tide::{
    sessions::{MemoryStore, SessionMiddleware, SessionStore},
    Middleware,
};
use url::Url;

use crate::{config::RootConfig, storage::Storage};

#[derive(Clone)]
pub struct State {
    config: Arc<RootConfig>,
    templates: Arc<Tera>,
    storage: Arc<Storage<PgPool>>,
    session_store: Arc<MemoryStore>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

impl State {
    pub fn new(config: RootConfig, templates: Tera, pool: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            templates: Arc::new(templates),
            storage: Arc::new(Storage::new(pool)),
            session_store: Arc::new(MemoryStore::new()),
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

    pub fn session_middleware(&self) -> impl Middleware<Self> {
        SessionMiddleware::new(
            self.clone(),
            b"some random value that we will figure out later",
        )
    }

    fn base(&self) -> Url {
        self.config.oauth2.issuer.clone()
    }

    pub fn issuer(&self) -> Url {
        self.base()
    }

    pub fn authorization_endpoint(&self) -> Option<Url> {
        self.base().join("oauth2/authorize").ok()
    }

    pub fn token_endpoint(&self) -> Option<Url> {
        self.base().join("oauth2/token").ok()
    }

    pub fn jwks_uri(&self) -> Option<Url> {
        self.base().join(".well-known/jwks.json").ok()
    }
}

#[async_trait]
impl SessionStore for State {
    async fn load_session(
        &self,
        cookie_value: String,
    ) -> anyhow::Result<Option<tide::sessions::Session>> {
        self.session_store.load_session(cookie_value).await
    }

    async fn store_session(
        &self,
        session: tide::sessions::Session,
    ) -> anyhow::Result<Option<String>> {
        self.session_store.store_session(session).await
    }

    async fn destroy_session(&self, session: tide::sessions::Session) -> anyhow::Result<()> {
        self.session_store.destroy_session(session).await
    }

    async fn clear_store(&self) -> anyhow::Result<()> {
        self.session_store.clear_store().await
    }
}
