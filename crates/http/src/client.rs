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

use std::convert::Infallible;

use hyper::client::{
    connect::dns::{GaiResolver, Name},
    HttpConnector,
};
pub use hyper::Client;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use mas_tower::{
    DurationRecorderLayer, DurationRecorderService, FnWrapper, InFlightCounterLayer,
    InFlightCounterService, TraceLayer, TraceService,
};
use thiserror::Error;
use tower::Layer;
use tracing::Span;

#[cfg(all(not(feature = "webpki-roots"), not(feature = "native-roots")))]
compile_error!("enabling the 'client' feature requires also enabling the 'webpki-roots' or the 'native-roots' features");

#[cfg(all(feature = "webpki-roots", feature = "native-roots"))]
compile_error!("'webpki-roots' and 'native-roots' features are mutually exclusive");

#[cfg(feature = "native-roots")]
static NATIVE_TLS_ROOTS: tokio::sync::OnceCell<rustls::RootCertStore> =
    tokio::sync::OnceCell::const_new();

#[cfg(feature = "native-roots")]
fn load_tls_roots_blocking() -> Result<rustls::RootCertStore, NativeRootsLoadError> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs()?;
    for cert in certs {
        roots.add(cert)?;
    }

    if roots.is_empty() {
        return Err(NativeRootsLoadError::Empty);
    }

    Ok(roots)
}

#[cfg(feature = "native-roots")]
async fn tls_roots() -> Result<rustls::RootCertStore, NativeRootsInitError> {
    NATIVE_TLS_ROOTS
        .get_or_try_init(|| async move {
            // Load the TLS config once in a blocking task because loading the system
            // certificates can take a long time (~200ms) on macOS
            let span = tracing::info_span!("load_tls_roots");
            let roots = tokio::task::spawn_blocking(|| {
                let _span = span.entered();
                load_tls_roots_blocking()
            })
            .await??;
            Ok(roots)
        })
        .await
        .cloned()
}

#[cfg(feature = "webpki-roots")]
#[allow(clippy::unused_async)]
async fn tls_roots() -> Result<rustls::RootCertStore, Infallible> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    Ok(root_store)
}

#[cfg(feature = "native-roots")]
#[derive(Error, Debug)]
#[error(transparent)]
pub enum NativeRootsInitError {
    RootsLoadError(#[from] NativeRootsLoadError),

    JoinError(#[from] tokio::task::JoinError),
}

#[derive(Error, Debug, Clone)]
pub enum ClientInitError {
    #[cfg(feature = "native-roots")]
    #[error(transparent)]
    TlsRootsInit(std::sync::Arc<NativeRootsInitError>),
}

#[cfg(feature = "native-roots")]
impl From<NativeRootsInitError> for ClientInitError {
    fn from(inner: NativeRootsInitError) -> Self {
        Self::TlsRootsInit(std::sync::Arc::new(inner))
    }
}

impl From<Infallible> for ClientInitError {
    fn from(e: Infallible) -> Self {
        match e {}
    }
}

#[cfg(feature = "native-roots")]
#[derive(Error, Debug)]
pub enum NativeRootsLoadError {
    #[error("could not load root certificates")]
    Io(#[from] std::io::Error),

    #[error("invalid root certificate")]
    Rustls(#[from] rustls::Error),

    #[error("no root certificate loaded")]
    Empty,
}

async fn make_tls_config() -> Result<rustls::ClientConfig, ClientInitError> {
    let roots = tls_roots().await?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(tls_config)
}

pub type UntracedClient<B> = hyper::Client<UntracedConnector, B>;
pub type TracedClient<B> = hyper::Client<TracedConnector, B>;

/// Create a basic Hyper HTTP & HTTPS client without any tracing
///
/// # Errors
///
/// Returns an error if it failed to load the TLS certificates
pub async fn make_untraced_client<B>() -> Result<UntracedClient<B>, ClientInitError>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
{
    let https = make_untraced_connector().await?;
    Ok(Client::builder().build(https))
}

/// Create a basic Hyper HTTP & HTTPS client which traces DNS requests
///
/// # Errors
///
/// Returns an error if it failed to load the TLS certificates
pub async fn make_traced_client<B>() -> Result<TracedClient<B>, ClientInitError>
where
    B: http_body::Body + Send,
    B::Data: Send,
{
    let https = make_traced_connector().await?;
    Ok(Client::builder().build(https))
}

pub type TraceResolver<S> =
    InFlightCounterService<DurationRecorderService<TraceService<S, FnWrapper<fn(&Name) -> Span>>>>;
pub type UntracedConnector = HttpsConnector<HttpConnector<GaiResolver>>;
pub type TracedConnector = HttpsConnector<HttpConnector<TraceResolver<GaiResolver>>>;

/// Create a traced HTTP and HTTPS connector
///
/// # Errors
///
/// Returns an error if it failed to load the TLS certificates
pub async fn make_traced_connector() -> Result<TracedConnector, ClientInitError>
where
{
    let in_flight_counter = InFlightCounterLayer::new("dns.resolve.active_requests");
    let duration_recorder = DurationRecorderLayer::new("dns.resolve.duration");
    let trace_layer = TraceLayer::from_fn(
        (|request: &Name| {
            tracing::info_span!(
                "dns.resolve",
                "otel.kind" = "client",
                "net.host.name" = %request,
            )
        }) as fn(&Name) -> Span,
    );

    let resolver = (in_flight_counter, duration_recorder, trace_layer).layer(GaiResolver::new());

    let tls_config = make_tls_config().await?;
    Ok(make_connector(resolver, tls_config))
}

async fn make_untraced_connector() -> Result<UntracedConnector, ClientInitError>
where
{
    let resolver = GaiResolver::new();
    let tls_config = make_tls_config().await?;
    Ok(make_connector(resolver, tls_config))
}

fn make_connector<R>(
    resolver: R,
    tls_config: rustls::ClientConfig,
) -> HttpsConnector<HttpConnector<R>> {
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}
