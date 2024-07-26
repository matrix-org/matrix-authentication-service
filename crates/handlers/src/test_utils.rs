// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

use std::{
    convert::Infallible,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
};

use axum::{
    async_trait,
    body::{Bytes, HttpBody},
    extract::{FromRef, FromRequestParts},
    response::{IntoResponse, IntoResponseParts},
};
use chrono::Duration;
use cookie_store::{CookieStore, RawCookie};
use futures_util::future::BoxFuture;
use headers::{Authorization, ContentType, HeaderMapExt, HeaderName, HeaderValue};
use hyper::{
    header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    Request, Response, StatusCode,
};
use mas_axum_utils::{
    cookies::{CookieJar, CookieManager},
    http_client_factory::HttpClientFactory,
    ErrorWrapper,
};
use mas_data_model::SiteConfig;
use mas_i18n::Translator;
use mas_keystore::{Encrypter, JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use mas_matrix::{BoxHomeserverConnection, HomeserverConnection, MockHomeserverConnection};
use mas_policy::{InstantiateError, Policy, PolicyFactory};
use mas_router::{SimpleRoute, UrlBuilder};
use mas_storage::{clock::MockClock, BoxClock, BoxRepository, BoxRng};
use mas_storage_pg::{DatabaseError, PgRepository};
use mas_templates::{SiteConfigExt, Templates};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::PgPool;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    graphql,
    passwords::{Hasher, PasswordManager},
    upstream_oauth2::cache::MetadataCache,
    ActivityTracker, BoundActivityTracker,
};

/// Setup rustcrypto and tracing for tests.
#[allow(unused_must_use)]
pub(crate) fn setup() {
    rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
}

pub(crate) async fn policy_factory(
    data: serde_json::Value,
) -> Result<Arc<PolicyFactory>, anyhow::Error> {
    let workspace_root = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let file = tokio::fs::File::open(workspace_root.join("policies").join("policy.wasm")).await?;

    let entrypoints = mas_policy::Entrypoints {
        register: "register/violation".to_owned(),
        client_registration: "client_registration/violation".to_owned(),
        authorization_grant: "authorization_grant/violation".to_owned(),
        email: "email/violation".to_owned(),
    };

    let policy_factory = PolicyFactory::load(file, data, entrypoints).await?;
    let policy_factory = Arc::new(policy_factory);
    Ok(policy_factory)
}

#[derive(Clone)]
pub(crate) struct TestState {
    pub pool: PgPool,
    pub templates: Templates,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub metadata_cache: MetadataCache,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_connection: Arc<MockHomeserverConnection>,
    pub policy_factory: Arc<PolicyFactory>,
    pub graphql_schema: graphql::Schema,
    pub http_client_factory: HttpClientFactory,
    pub password_manager: PasswordManager,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub clock: Arc<MockClock>,
    pub rng: Arc<Mutex<ChaChaRng>>,
}

fn workspace_root() -> camino::Utf8PathBuf {
    camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize_utf8()
        .unwrap()
}

pub fn test_site_config() -> SiteConfig {
    SiteConfig {
        access_token_ttl: Duration::try_minutes(5).unwrap(),
        compat_token_ttl: Duration::try_minutes(5).unwrap(),
        server_name: "example.com".to_owned(),
        policy_uri: Some("https://example.com/policy".parse().unwrap()),
        tos_uri: Some("https://example.com/tos".parse().unwrap()),
        imprint: None,
        password_login_enabled: true,
        password_registration_enabled: true,
        email_change_allowed: true,
        displayname_change_allowed: true,
        password_change_allowed: true,
        account_recovery_allowed: true,
        captcha: None,
        minimum_password_complexity: 1,
    }
}

impl TestState {
    /// Create a new test state from the given database pool
    pub async fn from_pool(pool: PgPool) -> Result<Self, anyhow::Error> {
        Self::from_pool_with_site_config(pool, test_site_config()).await
    }

    /// Create a new test state from the given database pool and site config
    pub async fn from_pool_with_site_config(
        pool: PgPool,
        site_config: SiteConfig,
    ) -> Result<Self, anyhow::Error> {
        let workspace_root = workspace_root();

        let url_builder = UrlBuilder::new("https://example.com/".parse()?, None, None);

        let templates = Templates::load(
            workspace_root.join("templates"),
            url_builder.clone(),
            workspace_root.join("frontend/dist/manifest.json"),
            workspace_root.join("translations"),
            site_config.templates_branding(),
            site_config.templates_features(),
        )
        .await?;

        // TODO: add more test keys to the store
        let rsa =
            PrivateKey::load_pem(include_str!("../../keystore/tests/keys/rsa.pkcs1.pem")).unwrap();
        let rsa = JsonWebKey::new(rsa).with_kid("test-rsa");

        let jwks = JsonWebKeySet::new(vec![rsa]);
        let key_store = Keystore::new(jwks);

        let encrypter = Encrypter::new(&[0x42; 32]);
        let cookie_manager = CookieManager::derive_from(url_builder.http_base(), &[0x42; 32]);

        let metadata_cache = MetadataCache::new();

        let password_manager = if site_config.password_login_enabled {
            PasswordManager::new(
                site_config.minimum_password_complexity,
                [(1, Hasher::argon2id(None))],
            )?
        } else {
            PasswordManager::disabled()
        };

        let policy_factory = policy_factory(serde_json::json!({})).await?;

        let homeserver_connection =
            Arc::new(MockHomeserverConnection::new(&site_config.server_name));

        let http_client_factory = HttpClientFactory::new();

        let clock = Arc::new(MockClock::default());
        let rng = Arc::new(Mutex::new(ChaChaRng::seed_from_u64(42)));

        let graphql_state = TestGraphQLState {
            pool: pool.clone(),
            policy_factory: Arc::clone(&policy_factory),
            homeserver_connection: Arc::clone(&homeserver_connection),
            site_config: site_config.clone(),
            rng: Arc::clone(&rng),
            clock: Arc::clone(&clock),
            password_manager: password_manager.clone(),
        };
        let state: crate::graphql::BoxState = Box::new(graphql_state);

        let graphql_schema = graphql::schema_builder().data(state).finish();

        let activity_tracker =
            ActivityTracker::new(pool.clone(), std::time::Duration::from_secs(1));

        Ok(Self {
            pool,
            templates,
            key_store,
            cookie_manager,
            metadata_cache,
            encrypter,
            url_builder,
            homeserver_connection,
            policy_factory,
            graphql_schema,
            http_client_factory,
            password_manager,
            site_config,
            activity_tracker,
            clock,
            rng,
        })
    }

    pub async fn request<B>(&self, request: Request<B>) -> Response<String>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        <B as HttpBody>::Error: std::error::Error + Send + Sync,
        B::Error: std::error::Error + Send + Sync,
        B::Data: Send,
    {
        let app = crate::healthcheck_router()
            .merge(crate::discovery_router())
            .merge(crate::api_router())
            .merge(crate::compat_router())
            .merge(crate::human_router(self.templates.clone()))
            .merge(crate::graphql_router(false))
            .with_state(self.clone())
            .into_service();

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
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("Failed to read response body");
        let body = std::str::from_utf8(&body)
            .expect("Response body is not valid UTF-8")
            .to_owned();

        Response::from_parts(parts, body)
    }

    pub async fn repository(&self) -> Result<BoxRepository, DatabaseError> {
        let repo = PgRepository::from_pool(&self.pool).await?;
        Ok(repo.boxed())
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

    /// Get an empty cookie jar
    pub fn cookie_jar(&self) -> CookieJar {
        self.cookie_manager.cookie_jar()
    }
}

struct TestGraphQLState {
    pool: PgPool,
    homeserver_connection: Arc<MockHomeserverConnection>,
    site_config: SiteConfig,
    policy_factory: Arc<PolicyFactory>,
    clock: Arc<MockClock>,
    rng: Arc<Mutex<ChaChaRng>>,
    password_manager: PasswordManager,
}

#[async_trait]
impl graphql::State for TestGraphQLState {
    async fn repository(&self) -> Result<BoxRepository, mas_storage::RepositoryError> {
        let repo = PgRepository::from_pool(&self.pool)
            .await
            .map_err(mas_storage::RepositoryError::from_error)?;

        Ok(repo.boxed())
    }

    async fn policy(&self) -> Result<Policy, InstantiateError> {
        self.policy_factory.instantiate().await
    }

    fn password_manager(&self) -> PasswordManager {
        self.password_manager.clone()
    }

    fn homeserver_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        &self.homeserver_connection
    }

    fn clock(&self) -> BoxClock {
        Box::new(self.clock.clone())
    }

    fn site_config(&self) -> &SiteConfig {
        &self.site_config
    }

    fn rng(&self) -> BoxRng {
        let mut parent_rng = self.rng.lock().expect("Failed to lock RNG");
        let rng = ChaChaRng::from_rng(&mut *parent_rng).expect("Failed to seed RNG");
        Box::new(rng)
    }
}

impl FromRef<TestState> for PgPool {
    fn from_ref(input: &TestState) -> Self {
        input.pool.clone()
    }
}

impl FromRef<TestState> for graphql::Schema {
    fn from_ref(input: &TestState) -> Self {
        input.graphql_schema.clone()
    }
}

impl FromRef<TestState> for Templates {
    fn from_ref(input: &TestState) -> Self {
        input.templates.clone()
    }
}

impl FromRef<TestState> for Arc<Translator> {
    fn from_ref(input: &TestState) -> Self {
        input.templates.translator()
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

impl FromRef<TestState> for CookieManager {
    fn from_ref(input: &TestState) -> Self {
        input.cookie_manager.clone()
    }
}

impl FromRef<TestState> for MetadataCache {
    fn from_ref(input: &TestState) -> Self {
        input.metadata_cache.clone()
    }
}

impl FromRef<TestState> for SiteConfig {
    fn from_ref(input: &TestState) -> Self {
        input.site_config.clone()
    }
}

impl FromRef<TestState> for BoxHomeserverConnection {
    fn from_ref(input: &TestState) -> Self {
        Box::new(input.homeserver_connection.clone())
    }
}

#[async_trait]
impl FromRequestParts<TestState> for ActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.activity_tracker.clone())
    }
}

#[async_trait]
impl FromRequestParts<TestState> for BoundActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        let ip = None;
        Ok(state.activity_tracker.clone().bind(ip))
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
        let mut parent_rng = state.rng.lock().expect("Failed to lock RNG");
        let rng = ChaChaRng::from_rng(&mut *parent_rng).expect("Failed to seed RNG");
        Ok(Box::new(rng))
    }
}

#[async_trait]
impl FromRequestParts<TestState> for BoxRepository {
    type Rejection = ErrorWrapper<mas_storage_pg::DatabaseError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        let repo = PgRepository::from_pool(&state.pool).await?;
        Ok(repo.boxed())
    }
}

#[async_trait]
impl FromRequestParts<TestState> for Policy {
    type Rejection = ErrorWrapper<mas_policy::InstantiateError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &TestState,
    ) -> Result<Self, Self::Rejection> {
        let policy = state.policy_factory.instantiate().await?;
        Ok(policy)
    }
}

pub(crate) trait RequestBuilderExt {
    /// Builds the request with the given JSON value as body.
    fn json<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Builds the request with the given form value as body.
    fn form<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Sets the request Authorization header to the given bearer token.
    fn bearer(self, token: &str) -> Self;

    /// Sets the request Authorization header to the given basic auth
    /// credentials.
    fn basic_auth(self, username: &str, password: &str) -> Self;

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

    fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::basic(username, password));
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

    /// Asserts that the response has the given header value.
    ///
    /// # Panics
    ///
    /// Panics if the response does not have the given header or if the header
    /// value does not match.
    fn assert_header_value(&self, header: HeaderName, value: &str);

    /// Get the response body as JSON.
    ///
    /// # Panics
    ///
    /// Panics if the response is missing the `Content-Type: application/json`,
    /// or if the body is not valid JSON.
    fn json<T: DeserializeOwned>(&self) -> T;
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

    #[track_caller]
    fn assert_header_value(&self, header: HeaderName, value: &str) {
        let actual_value = self
            .headers()
            .get(&header)
            .unwrap_or_else(|| panic!("Missing header {header}"));

        assert_eq!(
            actual_value,
            value,
            "Header mismatch: got {:?}, expected {:?}",
            self.headers().get(header),
            value
        );
    }

    #[track_caller]
    fn json<T: DeserializeOwned>(&self) -> T {
        self.assert_header_value(CONTENT_TYPE, "application/json");
        serde_json::from_str(self.body()).expect("JSON deserialization failed")
    }
}

/// A helper for storing and retrieving cookies in tests.
#[derive(Clone, Debug, Default)]
pub struct CookieHelper {
    store: Arc<RwLock<CookieStore>>,
}

impl CookieHelper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject the cookies from the store into the request.
    pub fn with_cookies<B>(&self, mut request: Request<B>) -> Request<B> {
        let url = Url::options()
            .base_url(Some(&"https://example.com/".parse().unwrap()))
            .parse(&request.uri().to_string())
            .expect("Failed to parse URL");

        let store = self.store.read().unwrap();
        let value = store
            .get_request_values(&url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");

        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&value).expect("Invalid cookie value"),
        );
        request
    }

    /// Save the cookies from the response into the store.
    pub fn save_cookies<B>(&self, response: &Response<B>) {
        let url = "https://example.com/".parse().unwrap();
        let mut store = self.store.write().unwrap();
        store.store_response_cookies(
            response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .map(|set_cookie| {
                    RawCookie::parse(
                        set_cookie
                            .to_str()
                            .expect("Invalid set-cookie header")
                            .to_owned(),
                    )
                    .expect("Invalid set-cookie header")
                }),
            &url,
        );
    }

    pub fn import(&self, res: impl IntoResponseParts) {
        let response = (res, "").into_response();
        self.save_cookies(&response);
    }
}

impl<S> Layer<S> for CookieHelper {
    type Service = CookieStoreService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieStoreService {
            helper: self.clone(),
            inner,
        }
    }
}

/// A middleware that stores and retrieves cookies.
pub struct CookieStoreService<S> {
    helper: CookieHelper,
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CookieStoreService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let req = self.helper.with_cookies(request);
        let inner = self.inner.call(req);
        let helper = self.helper.clone();
        Box::pin(async move {
            let response: Response<_> = inner.await?;
            helper.save_cookies(&response);
            Ok(response)
        })
    }
}
