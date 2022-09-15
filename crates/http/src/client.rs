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

use std::{convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http::{Request, Response};
use http_body::{combinators::BoxBody, Body};
use hyper::{
    client::{
        connect::dns::{GaiResolver, Name},
        HttpConnector,
    },
    Client,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use thiserror::Error;
use tower::{util::BoxCloneService, Service, ServiceBuilder, ServiceExt};

use crate::{
    layers::{
        client::{ClientLayer, ClientResponse},
        otel::{TraceDns, TraceLayer},
    },
    BoxError,
};

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
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert)?;
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
async fn tls_roots() -> Result<rustls::RootCertStore, Infallible> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    Ok(roots)
}

#[cfg(feature = "native-roots")]
#[derive(Error, Debug)]
#[error(transparent)]
pub enum NativeRootsInitError {
    RootsLoadError(#[from] NativeRootsLoadError),

    JoinError(#[from] tokio::task::JoinError),
}

/// A wrapper over a boxed error that implements ``std::error::Error``.
/// This is helps converting to ``anyhow::Error`` with the `?` operator
#[derive(Error, Debug)]
#[error(transparent)]
pub struct ClientError {
    #[from]
    inner: BoxError,
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
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

#[cfg(feature = "native-roots")]
#[derive(Error, Debug)]
pub enum NativeRootsLoadError {
    #[error("could not load root certificates")]
    Io(#[from] std::io::Error),

    #[error("invalid root certificate")]
    Webpki(#[from] webpki::Error),

    #[error("no root certificate loaded")]
    Empty,
}

/// Create a basic Hyper HTTP & HTTPS client without any tracing
///
/// # Errors
///
/// Returns an error if it failed to load the TLS certificates
pub async fn make_untraced_client<B, E>(
) -> Result<hyper::Client<HttpsConnector<HttpConnector<GaiResolver>>, B>, ClientInitError>
where
    B: http_body::Body<Data = Bytes, Error = E> + Send + 'static,
    E: Into<BoxError>,
{
    let resolver = GaiResolver::new();
    let roots = tls_roots().await?;
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(make_client(resolver, tls_config))
}

async fn make_base_client<B, E>(
) -> Result<hyper::Client<HttpsConnector<HttpConnector<TraceDns<GaiResolver>>>, B>, ClientInitError>
where
    B: http_body::Body<Data = Bytes, Error = E> + Send + 'static,
    E: Into<BoxError>,
{
    // Trace DNS requests
    let resolver = ServiceBuilder::new()
        .layer(TraceLayer::dns())
        .service(GaiResolver::new());

    let roots = tls_roots().await?;
    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(make_client(resolver, tls_config))
}

fn make_client<R, B, E>(
    resolver: R,
    tls_config: rustls::ClientConfig,
) -> hyper::Client<HttpsConnector<HttpConnector<R>>, B>
where
    R: Service<Name> + Send + Sync + Clone + 'static,
    R::Error: std::error::Error + Send + Sync,
    R::Future: Send,
    R::Response: Iterator<Item = SocketAddr>,
    B: http_body::Body<Data = Bytes, Error = E> + Send + 'static,
    E: Into<BoxError>,
{
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    Client::builder().build(https)
}

/// Create a traced HTTP client, with a default timeout, which follows redirects
/// and handles compression
///
/// # Errors
///
/// Returns an error if it failed to initialize
pub async fn client<B, E>(
    operation: &'static str,
) -> Result<
    BoxCloneService<Request<B>, Response<BoxBody<bytes::Bytes, ClientError>>, ClientError>,
    ClientInitError,
>
where
    B: http_body::Body<Data = Bytes, Error = E> + Default + Send + 'static,
    E: Into<BoxError> + 'static,
{
    let client = make_base_client().await?;

    let client = ServiceBuilder::new()
        // Convert the errors to ClientError to help dealing with them
        .map_err(ClientError::from)
        .map_response(|r: ClientResponse<hyper::Body>| {
            r.map(|body| body.map_err(ClientError::from).boxed())
        })
        .layer(ClientLayer::new(operation))
        .service(client)
        .boxed_clone();

    Ok(client)
}
