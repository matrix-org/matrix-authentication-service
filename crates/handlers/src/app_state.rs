// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::{convert::Infallible, sync::Arc};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
};
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_email::Mailer;
use mas_keystore::{Encrypter, Keystore};
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRng, SystemClock};
use mas_templates::Templates;
use rand::SeedableRng;
use sqlx::PgPool;

use crate::{passwords::PasswordManager, MatrixHomeserver};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub templates: Templates,
    pub key_store: Keystore,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub mailer: Mailer,
    pub homeserver: MatrixHomeserver,
    pub policy_factory: Arc<PolicyFactory>,
    pub graphql_schema: mas_graphql::Schema,
    pub http_client_factory: HttpClientFactory,
    pub password_manager: PasswordManager,
}

impl FromRef<AppState> for PgPool {
    fn from_ref(input: &AppState) -> Self {
        input.pool.clone()
    }
}

impl FromRef<AppState> for mas_graphql::Schema {
    fn from_ref(input: &AppState) -> Self {
        input.graphql_schema.clone()
    }
}

impl FromRef<AppState> for Templates {
    fn from_ref(input: &AppState) -> Self {
        input.templates.clone()
    }
}

impl FromRef<AppState> for Keystore {
    fn from_ref(input: &AppState) -> Self {
        input.key_store.clone()
    }
}

impl FromRef<AppState> for Encrypter {
    fn from_ref(input: &AppState) -> Self {
        input.encrypter.clone()
    }
}

impl FromRef<AppState> for UrlBuilder {
    fn from_ref(input: &AppState) -> Self {
        input.url_builder.clone()
    }
}

impl FromRef<AppState> for Mailer {
    fn from_ref(input: &AppState) -> Self {
        input.mailer.clone()
    }
}

impl FromRef<AppState> for MatrixHomeserver {
    fn from_ref(input: &AppState) -> Self {
        input.homeserver.clone()
    }
}

impl FromRef<AppState> for Arc<PolicyFactory> {
    fn from_ref(input: &AppState) -> Self {
        input.policy_factory.clone()
    }
}

impl FromRef<AppState> for HttpClientFactory {
    fn from_ref(input: &AppState) -> Self {
        input.http_client_factory.clone()
    }
}

impl FromRef<AppState> for PasswordManager {
    fn from_ref(input: &AppState) -> Self {
        input.password_manager.clone()
    }
}

#[async_trait]
impl FromRequestParts<AppState> for BoxClock {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let clock = SystemClock::default();
        Ok(Box::new(clock))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for BoxRng {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // This rng is used to source the local rng
        #[allow(clippy::disallowed_methods)]
        let rng = rand::thread_rng();

        let rng = rand_chacha::ChaChaRng::from_rng(rng).expect("Failed to seed RNG");
        Ok(Box::new(rng))
    }
}
