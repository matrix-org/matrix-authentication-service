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

use std::{convert::Infallible, sync::Arc};

use axum::{
    async_trait,
    body::HttpBody,
    extract::{FromRef, FromRequestParts},
};
use headers::{Authorization, ContentType, HeaderMapExt};
use hyper::{Request, Response, StatusCode};
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_email::{MailTransport, Mailer};
use mas_keystore::{Encrypter, JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use mas_policy::PolicyFactory;
use mas_router::{SimpleRoute, UrlBuilder};
use mas_storage::{clock::MockClock, BoxClock, BoxRepository, BoxRng, Repository};
use mas_storage_pg::PgRepository;
use mas_templates::Templates;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Mutex;
use tower::{Service, ServiceExt};

use crate::{
    app_state::RepositoryError,
    graphql_schema,
    passwords::{Hasher, PasswordManager},
    MatrixHomeserver,
};

pub(crate) fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
}

#[derive(Clone)]
pub(crate) struct TestState {
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
    pub clock: Arc<MockClock>,
    pub rng: Arc<Mutex<ChaChaRng>>,
}

impl TestState {
    /// Create a new test state from the given database pool
    pub async fn from_pool(pool: PgPool) -> Result<Self, anyhow::Error> {
        let workspace_root = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");

        let url_builder = UrlBuilder::new("https://example.com/".parse()?);

        let templates =
            Templates::load(workspace_root.join("templates"), url_builder.clone()).await?;

        // TODO: add more test keys to the store
        let rsa =
            PrivateKey::load_pem(include_str!("../../keystore/tests/keys/rsa.pkcs1.pem")).unwrap();
        let rsa = JsonWebKey::new(rsa).with_kid("test-rsa");

        let jwks = JsonWebKeySet::new(vec![rsa]);
        let key_store = Keystore::new(jwks);

        let encrypter = Encrypter::new(&[0x42; 32]);

        let password_manager = PasswordManager::new([(1, Hasher::argon2id(None))])?;

        let transport = MailTransport::blackhole();
        let mailbox: lettre::message::Mailbox = "server@example.com".parse()?;
        let mailer = Mailer::new(templates.clone(), transport, mailbox.clone(), mailbox);

        let homeserver = MatrixHomeserver::new("example.com".to_owned());

        let file =
            tokio::fs::File::open(workspace_root.join("policies").join("policy.wasm")).await?;

        let policy_factory = PolicyFactory::load(
            file,
            serde_json::json!({}),
            "register/violation".to_owned(),
            "client_registration/violation".to_owned(),
            "authorization_grant/violation".to_owned(),
        )
        .await?;

        let policy_factory = Arc::new(policy_factory);

        let graphql_schema = graphql_schema();

        let http_client_factory = HttpClientFactory::new(10);

        let clock = Arc::new(MockClock::default());
        let rng = Arc::new(Mutex::new(ChaChaRng::seed_from_u64(42)));

        Ok(Self {
            pool,
            templates,
            key_store,
            encrypter,
            url_builder,
            mailer,
            homeserver,
            policy_factory,
            graphql_schema,
            http_client_factory,
            password_manager,
            clock,
            rng,
        })
    }

    pub async fn request<B>(&self, request: Request<B>) -> Response<String>
    where
        B: HttpBody + Send + 'static,
        B::Error: std::error::Error + Send + Sync,
        B::Data: Send,
    {
        let app = crate::healthcheck_router()
            .merge(crate::discovery_router())
            .merge(crate::api_router())
            .merge(crate::compat_router())
            .merge(crate::human_router(self.templates.clone()))
            .with_state(self.clone());

        // Both unwrap are on Infallible, so this is safe
        let response = app
            .ready_oneshot()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();

        let (parts, body) = response.into_parts();

        // This could actually fail, but do we really care about that?
        let body = hyper::body::to_bytes(body)
            .await
            .expect("Failed to read response body");
        let body = std::str::from_utf8(&body)
            .expect("Response body is not valid UTF-8")
            .to_owned();

        Response::from_parts(parts, body)
    }

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(&self.pool).await?;
        Ok(repo
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed())
    }

    /// Returns a new random number generator.
    ///
    /// # Panics
    ///
    /// Panics if the RNG is already locked.
    pub fn rng(&self) -> ChaChaRng {
        let mut parent_rng = self.rng.try_lock().expect("Failed to lock RNG");
        ChaChaRng::from_rng(&mut *parent_rng).unwrap()
    }

    /// Do a call to the userinfo endpoint to check if the given token is valid.
    /// Returns true if the token is valid.
    ///
    /// # Panics
    ///
    /// Panics if the response status code is not 200 or 401.
    pub async fn is_access_token_valid(&self, token: &str) -> bool {
        let request = Request::get(mas_router::OidcUserinfo::PATH)
            .bearer(token)
            .empty();

        let response = self.request(request).await;

        match response.status() {
            StatusCode::OK => true,
            StatusCode::UNAUTHORIZED => false,
            _ => panic!("Unexpected status code: {}", response.status()),
        }
    }
}

impl FromRef<TestState> for PgPool {
    fn from_ref(input: &TestState) -> Self {
        input.pool.clone()
    }
}

impl FromRef<TestState> for mas_graphql::Schema {
    fn from_ref(input: &TestState) -> Self {
        input.graphql_schema.clone()
    }
}

impl FromRef<TestState> for Templates {
    fn from_ref(input: &TestState) -> Self {
        input.templates.clone()
    }
}

impl FromRef<TestState> for Keystore {
    fn from_ref(input: &TestState) -> Self {
        input.key_store.clone()
    }
}

impl FromRef<TestState> for Encrypter {
    fn from_ref(input: &TestState) -> Self {
        input.encrypter.clone()
    }
}

impl FromRef<TestState> for UrlBuilder {
    fn from_ref(input: &TestState) -> Self {
        input.url_builder.clone()
    }
}

impl FromRef<TestState> for Mailer {
    fn from_ref(input: &TestState) -> Self {
        input.mailer.clone()
    }
}

impl FromRef<TestState> for MatrixHomeserver {
    fn from_ref(input: &TestState) -> Self {
        input.homeserver.clone()
    }
}

impl FromRef<TestState> for Arc<PolicyFactory> {
    fn from_ref(input: &TestState) -> Self {
        input.policy_factory.clone()
    }
}

impl FromRef<TestState> for HttpClientFactory {
    fn from_ref(input: &TestState) -> Self {
        input.http_client_factory.clone()
    }
}

impl FromRef<TestState> for PasswordManager {
    fn from_ref(input: &TestState) -> Self {
        input.password_manager.clone()
    }
}

#[async_trait]
impl FromRequestParts<TestState> for BoxClock {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Box::new(state.clock.clone()))
    }
}

#[async_trait]
impl FromRequestParts<TestState> for BoxRng {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        let mut parent_rng = state.rng.lock().await;
        let rng = ChaChaRng::from_rng(&mut *parent_rng).expect("Failed to seed RNG");
        Ok(Box::new(rng))
    }
}

#[async_trait]
impl FromRequestParts<TestState> for BoxRepository {
    type Rejection = RepositoryError;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        let repo = PgRepository::from_pool(&state.pool).await?;
        Ok(repo
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed())
    }
}

pub(crate) trait RequestBuilderExt {
    /// Builds the request with the given JSON value as body.
    fn json<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Builds the request with the given form value as body.
    fn form<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Sets the request Authorization header to the given bearer token.
    fn bearer(self, token: &str) -> Self;

    /// Builds the request with an empty body.
    fn empty(self) -> hyper::Request<String>;
}

impl RequestBuilderExt for hyper::http::request::Builder {
    fn json<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::json());

        self.body(serde_json::to_string(&body).unwrap()).unwrap()
    }

    fn form<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::form_url_encoded());

        self.body(serde_urlencoded::to_string(&body).unwrap())
            .unwrap()
    }

    fn bearer(mut self, token: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::bearer(token).unwrap());
        self
    }

    fn empty(self) -> hyper::Request<String> {
        self.body(String::new()).unwrap()
    }
}

pub(crate) trait ResponseExt {
    /// Asserts that the response has the given status code.
    ///
    /// # Panics
    ///
    /// Panics if the response has a different status code.
    fn assert_status(&self, status: StatusCode);
}

impl ResponseExt for Response<String> {
    #[track_caller]
    fn assert_status(&self, status: StatusCode) {
        assert_eq!(
            self.status(),
            status,
            "HTTP status code mismatch: got {}, expected {}. Body: {}",
            self.status(),
            status,
            self.body()
        );
    }
}
