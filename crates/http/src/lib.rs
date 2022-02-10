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

use std::{marker::PhantomData, time::Duration};

use bytes::Bytes;
use http::{header::USER_AGENT, HeaderValue, Request, Response, Version};
use http_body::{combinators::BoxBody, Body};
use hyper::{client::HttpConnector, Client};
use hyper_rustls::{ConfigBuilderExt, HttpsConnectorBuilder};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_http::HeaderExtractor;
use tokio::sync::OnceCell;
use tower::{
    limit::ConcurrencyLimitLayer, timeout::TimeoutLayer, util::BoxCloneService, Layer, Service,
    ServiceBuilder, ServiceExt,
};
use tower_http::{
    compression::{CompressionBody, CompressionLayer},
    decompression::{DecompressionBody, DecompressionLayer},
    follow_redirect::FollowRedirectLayer,
    set_header::SetRequestHeaderLayer,
    trace::{MakeSpan, OnResponse, TraceLayer},
};
use tracing::field;
use tracing_opentelemetry::OpenTelemetrySpanExt;

static MAS_USER_AGENT: HeaderValue =
    HeaderValue::from_static("matrix-authentication-service/0.0.1");

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct ClientLayer<ReqBody> {
    operation: &'static str,
    _t: PhantomData<ReqBody>,
}

impl<B> ClientLayer<B> {
    fn new(operation: &'static str) -> Self {
        Self {
            operation,
            _t: PhantomData,
        }
    }
}

type ClientResponse<B> = Response<
    DecompressionBody<BoxBody<<B as http_body::Body>::Data, <B as http_body::Body>::Error>>,
>;

impl<ReqBody, ResBody, S> Layer<S> for ClientLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ReqBody: http_body::Body + Default + Send + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    ResBody::Error: std::fmt::Display + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
{
    type Service = BoxCloneService<Request<ReqBody>, ClientResponse<ResBody>, BoxError>;

    fn layer(&self, inner: S) -> Self::Service {
        ServiceBuilder::new()
            .layer(DecompressionLayer::new())
            .map_response(|r: Response<_>| r.map(BoxBody::new))
            .layer(SetRequestHeaderLayer::overriding(
                USER_AGENT,
                MAS_USER_AGENT.clone(),
            ))
            // A trace that has the whole operation, with all the redirects, retries, rate limits
            .layer(MakeOtelSpan::outer_client(self.operation).http_layer())
            .layer(ConcurrencyLimitLayer::new(10))
            .layer(FollowRedirectLayer::new())
            // A trace for each "real" http request
            .layer(MakeOtelSpan::inner_client().http_layer())
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
            // Propagate the span context
            .map_request(|mut r: Request<_>| {
                // TODO: this seems to be broken
                let cx = tracing::Span::current().context();
                let mut injector = opentelemetry_http::HeaderInjector(r.headers_mut());
                opentelemetry::global::get_text_map_propagator(|propagator| {
                    propagator.inject_context(&cx, &mut injector)
                });

                r
            })
            .service(inner)
            .boxed_clone()
    }
}

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

#[derive(Debug, Default)]
pub struct ServerLayer<ReqBody>(PhantomData<ReqBody>);

impl<ReqBody, ResBody, S> Layer<S> for ServerLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ReqBody: http_body::Body + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    ResBody::Error: std::fmt::Display + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
{
    type Service = BoxCloneService<
        Request<ReqBody>,
        Response<CompressionBody<BoxBody<ResBody::Data, ResBody::Error>>>,
        BoxError,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .map_response(|r: Response<_>| r.map(BoxBody::new))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(MakeOtelSpan::server())
                    .on_response(OtelOnResponse),
            )
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
            .service(inner)
            .boxed_clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MakeOtelSpan {
    OuterClient(&'static str),
    InnerClient,
    Server,
}

impl MakeOtelSpan {
    const fn outer_client(operation: &'static str) -> Self {
        Self::OuterClient(operation)
    }

    const fn inner_client() -> Self {
        Self::InnerClient
    }

    const fn server() -> Self {
        Self::Server
    }

    fn http_layer(
        self,
    ) -> TraceLayer<
        tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
        Self,
        tower_http::trace::DefaultOnRequest,
        OtelOnResponse,
    > {
        TraceLayer::new_for_http()
            .make_span_with(self)
            .on_response(OtelOnResponse)
    }
}

impl<B> MakeSpan<B> for MakeOtelSpan {
    fn make_span(&mut self, request: &Request<B>) -> tracing::Span {
        // Extract the context from the headers
        let headers = request.headers();

        let version = match request.version() {
            Version::HTTP_09 => "0.9",
            Version::HTTP_10 => "1.0",
            Version::HTTP_11 => "1.1",
            Version::HTTP_2 => "2.0",
            Version::HTTP_3 => "3.0",
            _ => "",
        };

        let span = match self {
            Self::OuterClient(operation) => {
                tracing::info_span!(
                    "client_request",
                    otel.name = operation,
                    otel.kind = "internal",
                    otel.status_code = field::Empty,
                    http.method = %request.method(),
                    http.target = %request.uri(),
                    http.flavor = version,
                    http.status_code = field::Empty,
                    http.user_agent = field::Empty,
                )
            }
            Self::InnerClient => {
                tracing::info_span!(
                    "outgoing_request",
                    otel.kind = "client",
                    otel.status_code = field::Empty,
                    http.method = %request.method(),
                    http.target = %request.uri(),
                    http.flavor = version,
                    http.status_code = field::Empty,
                    http.user_agent = field::Empty,
                )
            }
            Self::Server => {
                let span = tracing::info_span!(
                    "incoming_request",
                    otel.kind = "server",
                    otel.status_code = field::Empty,
                    http.method = %request.method(),
                    http.target = %request.uri(),
                    http.flavor = version,
                    http.status_code = field::Empty,
                    http.user_agent = field::Empty,
                );

                // Extract the context from the headers for server spans
                let headers = request.headers();
                let extractor = HeaderExtractor(headers);

                let cx = opentelemetry::global::get_text_map_propagator(|propagator| {
                    propagator.extract(&extractor)
                });

                if cx.span().span_context().is_remote() {
                    span.set_parent(cx);
                }

                span
            }
        };

        if let Some(user_agent) = headers.get(USER_AGENT).and_then(|s| s.to_str().ok()) {
            span.record("http.user_agent", &user_agent);
        }

        span
    }
}

#[derive(Debug, Clone, Default)]
pub struct OtelOnResponse;

impl<B> OnResponse<B> for OtelOnResponse {
    fn on_response(self, response: &hyper::Response<B>, _latency: Duration, span: &tracing::Span) {
        let s = response.status();
        let status = if s.is_success() {
            "ok"
        } else if s.is_client_error() || s.is_server_error() {
            "error"
        } else {
            "unset"
        };
        span.record("otel.status_code", &status);
        span.record("http.status_code", &s.as_u16());
    }
}
