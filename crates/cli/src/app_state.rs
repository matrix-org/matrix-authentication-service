// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

use std::{convert::Infallible, net::IpAddr, sync::Arc, time::Instant};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
};
use ipnetwork::IpNetwork;
use mas_data_model::SiteConfig;
use mas_handlers::{
    passwords::PasswordManager, ActivityTracker, BoundActivityTracker, CookieManager, ErrorWrapper,
    GraphQLSchema, HttpClientFactory, MetadataCache,
};
use mas_i18n::Translator;
use mas_keystore::{Encrypter, Keystore};
use mas_matrix::BoxHomeserverConnection;
use mas_matrix_synapse::SynapseConnection;
use mas_policy::{Policy, PolicyFactory};
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, Repository, SystemClock};
use mas_storage_pg::PgRepository;
use mas_templates::Templates;
use opentelemetry::{
    metrics::{Histogram, MetricsError},
    KeyValue,
};
use rand::SeedableRng;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub templates: Templates,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_connection: SynapseConnection,
    pub policy_factory: Arc<PolicyFactory>,
    pub graphql_schema: GraphQLSchema,
    pub http_client_factory: HttpClientFactory,
    pub password_manager: PasswordManager,
    pub metadata_cache: MetadataCache,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub trusted_proxies: Vec<IpNetwork>,
    pub conn_acquisition_histogram: Option<Histogram<u64>>,
}

impl AppState {
    /// Init the metrics for the app state.
    ///
    /// # Errors
    ///
    /// Returns an error if the metrics could not be initialized.
    pub fn init_metrics(&mut self) -> Result<(), MetricsError> {
        // XXX: do we want to put that somewhere else?
        let meter = opentelemetry::global::meter_with_version(
            env!("CARGO_PKG_NAME"),
            Some(env!("CARGO_PKG_VERSION")),
            Some(opentelemetry_semantic_conventions::SCHEMA_URL),
            None,
        );
        let pool = self.pool.clone();
        let usage = meter
            .i64_observable_up_down_counter("db.connections.usage")
            .with_description("The number of connections that are currently in `state` described by the state attribute.")
            .with_unit("{connection}")
            .init();

        let max = meter
            .i64_observable_up_down_counter("db.connections.max")
            .with_description("The maximum number of open connections allowed.")
            .with_unit("{connection}")
            .init();

        // Observe the number of active and idle connections in the pool
        meter.register_callback(&[usage.as_any(), max.as_any()], move |observer| {
            let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
            let used = pool.size() - idle;
            let max_conn = pool.options().get_max_connections();
            observer.observe_i64(&usage, i64::from(idle), &[KeyValue::new("state", "idle")]);
            observer.observe_i64(&usage, i64::from(used), &[KeyValue::new("state", "used")]);
            observer.observe_i64(&max, i64::from(max_conn), &[]);
        })?;

        // Track the connection acquisition time
        let histogram = meter
            .u64_histogram("db.client.connections.create_time")
            .with_description("The time it took to create a new connection.")
            .with_unit("ms")
            .init();
        self.conn_acquisition_histogram = Some(histogram);

        Ok(())
    }

    /// Init the metadata cache.
    ///
    /// # Panics
    ///
    /// Panics if the metadata cache could not be initialized.
    pub async fn init_metadata_cache(&self) {
        // XXX: this panics because the error is annoying to propagate
        let conn = self
            .pool
            .acquire()
            .await
            .expect("Failed to acquire a database connection");

        let mut repo = PgRepository::from_conn(conn);

        let http_service = self
            .http_client_factory
            .http_service("upstream_oauth2.metadata");

        self.metadata_cache
            .warm_up_and_run(
                http_service,
                std::time::Duration::from_secs(60 * 15),
                &mut repo,
            )
            .await
            .expect("Failed to warm up the metadata cache");
    }
}

impl FromRef<AppState> for PgPool {
    fn from_ref(input: &AppState) -> Self {
        input.pool.clone()
    }
}

impl FromRef<AppState> for GraphQLSchema {
    fn from_ref(input: &AppState) -> Self {
        input.graphql_schema.clone()
    }
}

impl FromRef<AppState> for Templates {
    fn from_ref(input: &AppState) -> Self {
        input.templates.clone()
    }
}

impl FromRef<AppState> for Arc<Translator> {
    fn from_ref(input: &AppState) -> Self {
        input.templates.translator()
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

impl FromRef<AppState> for CookieManager {
    fn from_ref(input: &AppState) -> Self {
        input.cookie_manager.clone()
    }
}

impl FromRef<AppState> for MetadataCache {
    fn from_ref(input: &AppState) -> Self {
        input.metadata_cache.clone()
    }
}

impl FromRef<AppState> for SiteConfig {
    fn from_ref(input: &AppState) -> Self {
        input.site_config.clone()
    }
}

impl FromRef<AppState> for BoxHomeserverConnection {
    fn from_ref(input: &AppState) -> Self {
        Box::new(input.homeserver_connection.clone())
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

#[async_trait]
impl FromRequestParts<AppState> for Policy {
    type Rejection = ErrorWrapper<mas_policy::InstantiateError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let policy = state.policy_factory.instantiate().await?;
        Ok(policy)
    }
}

#[async_trait]
impl FromRequestParts<AppState> for ActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.activity_tracker.clone())
    }
}

fn infer_client_ip(
    parts: &axum::http::request::Parts,
    trusted_proxies: &[IpNetwork],
) -> Option<IpAddr> {
    let connection_info = parts.extensions.get::<mas_listener::ConnectionInfo>();

    let peer = if let Some(info) = connection_info {
        // We can always trust the proxy protocol to give us the correct IP address
        if let Some(proxy) = info.get_proxy_ref() {
            if let Some(source) = proxy.source() {
                return Some(source.ip());
            }
        }

        info.get_peer_addr().map(|addr| addr.ip())
    } else {
        None
    };

    // Get the list of IPs from the X-Forwarded-For header
    let peers_from_header = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.parse().ok()))
        .into_iter()
        .flatten();

    // This constructs a list of IP addresses that might be the client's IP address.
    // Each intermediate proxy is supposed to add the client's IP address to front
    // of the list. We are effectively adding the IP we got from the socket to the
    // front of the list.
    let peer_list: Vec<IpAddr> = peer.into_iter().chain(peers_from_header).collect();

    // We'll fallback to the first IP in the list if all the IPs we got are trusted
    let fallback = peer_list.first().copied();

    // Now we go through the list, and the IP of the client is the first IP that is
    // not in the list of trusted proxies, starting from the back.
    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}

#[async_trait]
impl FromRequestParts<AppState> for BoundActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip = infer_client_ip(parts, &state.trusted_proxies);
        tracing::debug!(ip = ?ip, "Inferred client IP address");
        Ok(state.activity_tracker.clone().bind(ip))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for BoxRepository {
    type Rejection = ErrorWrapper<mas_storage_pg::DatabaseError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let start = Instant::now();
        let repo = PgRepository::from_pool(&state.pool).await?;

        // Measure the time it took to create the connection
        let duration = start.elapsed();
        let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);

        if let Some(histogram) = &state.conn_acquisition_histogram {
            histogram.record(duration_ms, &[]);
        }

        Ok(repo
            .map_err(mas_storage::RepositoryError::from_error)
            .boxed())
    }
}
