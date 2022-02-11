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

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use hyper::{client::HttpConnector, Client};
use hyper_rustls::{ConfigBuilderExt, HttpsConnectorBuilder};
use layers::client::ClientResponse;
use tokio::sync::OnceCell;
use tower::{util::BoxCloneService, ServiceBuilder, ServiceExt};

mod ext;
mod layers;

pub use self::{
    ext::ServiceExt as HttpServiceExt,
    layers::{client::ClientLayer, json::JsonResponseLayer, server::ServerLayer},
};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

static TLS_CONFIG: OnceCell<rustls::ClientConfig> = OnceCell::const_new();

pub async fn client<B, E>(
    operation: &'static str,
) -> anyhow::Result<
    BoxCloneService<
        Request<B>,
        Response<impl http_body::Body<Data = bytes::Bytes, Error = anyhow::Error>>,
        anyhow::Error,
    >,
>
where
    B: http_body::Body<Data = Bytes, Error = E> + Default + Send + 'static,
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
        .await?;

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config.clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    // TODO: we should get the remote address here
    let client = Client::builder().build(https);

    let client = ServiceBuilder::new()
        // Convert the errors to anyhow::Error for convenience
        .map_err(|e: BoxError| anyhow::anyhow!(e))
        .map_response(|r: ClientResponse<hyper::Body>| {
            r.map(|body| body.map_err(|e: BoxError| anyhow::anyhow!(e)))
        })
        .layer(ClientLayer::new(operation))
        .service(client)
        .boxed_clone();

    Ok(client)
}
