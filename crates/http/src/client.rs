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
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
pub use hyper_util::client::legacy::Client;
use hyper_util::{
    client::legacy::connect::{
        dns::{GaiResolver, Name},
        HttpConnector,
    },
    rt::TokioExecutor,
};
use mas_tower::{
    DurationRecorderLayer, DurationRecorderService, FnWrapper, InFlightCounterLayer,
    InFlightCounterService, TraceLayer, TraceService,
};
use opentelemetry_http::HttpClient;
use opentelemetry_semantic_conventions::trace::SERVER_ADDRESS;
use tower::Layer;
use tracing::Span;

pub type UntracedClient<B> = Client<UntracedConnector, B>;
pub type TracedClient<B> = Client<TracedConnector, B>;

/// Create a basic Hyper HTTP & HTTPS client without any tracing
#[must_use]
pub fn make_untraced_client<B>() -> UntracedClient<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
{
    let https = make_untraced_connector();
    Client::builder(TokioExecutor::new()).build(https)
}

pub type TraceResolver<S> =
    InFlightCounterService<DurationRecorderService<TraceService<S, FnWrapper<fn(&Name) -> Span>>>>;
pub type UntracedConnector = HttpsConnector<HttpConnector<GaiResolver>>;
pub type TracedConnector = HttpsConnector<HttpConnector<TraceResolver<GaiResolver>>>;

/// Create a traced HTTP and HTTPS connector
#[must_use]
pub fn make_traced_connector() -> TracedConnector
where
{
    let in_flight_counter = InFlightCounterLayer::new("dns.resolve.active_requests");
    let duration_recorder = DurationRecorderLayer::new("dns.resolve.duration");
    let trace_layer = TraceLayer::from_fn(
        (|request: &Name| {
            tracing::info_span!(
                "dns.lookup",
                "otel.kind" = "client",
                { SERVER_ADDRESS } = %request,

            )
        }) as fn(&Name) -> Span,
    );

    let resolver = (in_flight_counter, duration_recorder, trace_layer).layer(GaiResolver::new());

    let tls_config = rustls_platform_verifier::tls_config();
    make_connector(resolver, tls_config)
}

fn make_untraced_connector() -> UntracedConnector
where
{
    let resolver = GaiResolver::new();
    let tls_config = rustls_platform_verifier::tls_config();
    make_connector(resolver, tls_config)
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

/// A client which can be used by opentelemetry-http to send request through
/// hyper 1.x
///
/// This is needed until OTEL upgrades to hyper 1.x
/// <https://github.com/open-telemetry/opentelemetry-rust/pull/1674>
#[derive(Debug)]
pub struct OtelClient {
    client: UntracedClient<Full<Bytes>>,
}

impl OtelClient {
    /// Create a new [`OtelClient`] from a [`UntracedClient`]
    #[must_use]
    pub fn new(client: UntracedClient<Full<Bytes>>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl HttpClient for OtelClient {
    async fn send(
        &self,
        request: opentelemetry_http::Request<Vec<u8>>,
    ) -> Result<opentelemetry_http::Response<Bytes>, opentelemetry_http::HttpError> {
        // This is the annoying part: converting the OTEL http0.2 request to a http1
        // request
        let (parts, body) = request.into_parts();
        let body = Full::new(Bytes::from(body));
        let mut request = http::Request::new(body);

        *request.uri_mut() = parts.uri.to_string().parse().unwrap();
        *request.method_mut() = match parts.method {
            http02::Method::GET => http::Method::GET,
            http02::Method::POST => http::Method::POST,
            http02::Method::PUT => http::Method::PUT,
            http02::Method::DELETE => http::Method::DELETE,
            http02::Method::HEAD => http::Method::HEAD,
            http02::Method::OPTIONS => http::Method::OPTIONS,
            http02::Method::CONNECT => http::Method::CONNECT,
            http02::Method::PATCH => http::Method::PATCH,
            http02::Method::TRACE => http::Method::TRACE,
            _ => return Err(opentelemetry_http::HttpError::from("Unsupported method")),
        };
        request
            .headers_mut()
            .extend(parts.headers.into_iter().map(|(k, v)| {
                (
                    k.map(|k| http::HeaderName::from_bytes(k.as_ref()).unwrap()),
                    http::HeaderValue::from_bytes(v.as_ref()).unwrap(),
                )
            }));

        // Send the request
        let response = self.client.request(request).await?;

        // Convert back the response
        let (parts, body) = response.into_parts();
        let body = body.collect().await?.to_bytes();
        let mut response = opentelemetry_http::Response::new(body);
        *response.status_mut() = parts.status.as_u16().try_into().unwrap();
        response
            .headers_mut()
            .extend(parts.headers.into_iter().map(|(k, v)| {
                (
                    k.map(|k| http02::HeaderName::from_bytes(k.as_ref()).unwrap()),
                    http02::HeaderValue::from_bytes(v.as_ref()).unwrap(),
                )
            }));

        Ok(response)
    }
}
