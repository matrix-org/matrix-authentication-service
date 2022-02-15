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

//! [`tower`] layers and services to help building HTTP client and servers

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    rustdoc::missing_crate_level_docs,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{FutureExt, TryFutureExt};
use http::{Request, Response};
use http_body::{combinators::BoxBody, Body};
use hyper::{client::HttpConnector, Client};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use layers::client::ClientResponse;
use thiserror::Error;
use tokio::{sync::OnceCell, task::JoinError};
use tower::{util::BoxCloneService, ServiceBuilder, ServiceExt};

mod ext;
mod future_service;
mod layers;

pub use self::{
    ext::ServiceExt as HttpServiceExt,
    future_service::FutureService,
    layers::{client::ClientLayer, json::JsonResponseLayer, server::ServerLayer},
};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A wrapper over a boxed error that implements ``std::error::Error``.
/// This is helps converting to ``anyhow::Error`` with the `?` operator
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("failed to initialize HTTPS client")]
    Init(#[from] ClientInitError),

    #[error(transparent)]
    Call(#[from] BoxError),
}

#[derive(Error, Debug, Clone)]
pub enum ClientInitError {
    #[error("failed to load system certificates")]
    CertificateLoad {
        #[from]
        inner: Arc<JoinError>, // That error is in an Arc to have the error implement Clone
    },
}

static TLS_CONFIG: OnceCell<rustls::ClientConfig> = OnceCell::const_new();

async fn make_base_client<B, E>(
) -> Result<hyper::Client<HttpsConnector<HttpConnector>, B>, ClientInitError>
where
    B: http_body::Body<Data = Bytes, Error = E> + Send + 'static,
    E: Into<BoxError>,
{
    // TODO: we could probably hook a tracing DNS resolver there
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let tls_config = TLS_CONFIG
        .get_or_try_init(|| async move {
            // Load the TLS config once in a blocking task because loading the system
            // certificates can take a long time (~200ms) on macOS
            let span = tracing::info_span!("load_certificates");
            tokio::task::spawn_blocking(|| {
                let _span = span.entered();
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_native_roots()
                    .with_no_client_auth()
            })
            .await
        })
        .await
        .map_err(|e| ClientInitError::from(Arc::new(e)))?;

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config.clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    // TODO: we should get the remote address here
    let client = Client::builder().build(https);

    Ok::<_, ClientInitError>(client)
}

#[must_use]
pub fn client<B, E: 'static>(
    operation: &'static str,
) -> BoxCloneService<Request<B>, Response<BoxBody<bytes::Bytes, ClientError>>, ClientError>
where
    B: http_body::Body<Data = Bytes, Error = E> + Default + Send + 'static,
    E: Into<BoxError>,
{
    let fut = make_base_client()
        // Map the error to a ClientError
        .map_ok(|s| s.map_err(|e| ClientError::from(BoxError::from(e))))
        // Wrap it in an Shared (Arc) to be able to Clone it
        .shared();

    let client: FutureService<_, _> = FutureService::new(fut);

    let client = ServiceBuilder::new()
        // Convert the errors to ClientError to help dealing with them
        .map_err(ClientError::from)
        .map_response(|r: ClientResponse<hyper::Body>| {
            r.map(|body| body.map_err(ClientError::from).boxed())
        })
        .layer(ClientLayer::new(operation))
        .service(client);

    client.boxed_clone()
}
