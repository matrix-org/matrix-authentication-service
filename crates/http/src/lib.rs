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

use std::time::Duration;

use http::{header::USER_AGENT, HeaderValue, Request, Response, Version};
use http_body::combinators::BoxBody;
use hyper::{client::HttpConnector, Client};
use hyper_rustls::HttpsConnectorBuilder;
use opentelemetry::trace::TraceContextExt;
use opentelemetry_http::HeaderExtractor;
use tower::{
    limit::ConcurrencyLimitLayer,
    timeout::TimeoutLayer,
    util::{BoxCloneService, BoxService},
    BoxError, Service, ServiceBuilder, ServiceExt,
};
use tower_http::{
    follow_redirect::FollowRedirectLayer,
    set_header::SetRequestHeaderLayer,
    trace::{MakeSpan, OnResponse, TraceLayer},
};
use tracing::field;

static MAS_USER_AGENT: HeaderValue =
    HeaderValue::from_static("matrix-authentication-service/0.0.1");

type Body = BoxBody<bytes::Bytes, BoxError>;

pub fn client(
    operation: &'static str,
) -> BoxService<
    Request<Body>,
    Response<impl http_body::Body<Data = bytes::Bytes, Error = hyper::Error>>,
    BoxError,
> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    let client = Client::builder().build(https);

    ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(MakeOtelSpan::client(operation))
                .on_response(OtelOnResponse),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(FollowRedirectLayer::new())
        .layer(ConcurrencyLimitLayer::new(10))
        .layer(SetRequestHeaderLayer::overriding(
            USER_AGENT,
            MAS_USER_AGENT.clone(),
        ))
        .service(client)
        .boxed()
}

#[allow(clippy::type_complexity)]
pub fn server<ReqBody, ResBody, S>(
    service: S,
) -> BoxCloneService<Request<ReqBody>, Response<BoxBody<ResBody::Data, ResBody::Error>>, BoxError>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ReqBody: http_body::Body + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    ResBody::Error: std::fmt::Display + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + 'static,
{
    ServiceBuilder::new()
        .map_response(|r: Response<_>| r.map(BoxBody::new))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(MakeOtelSpan::server())
                .on_response(OtelOnResponse),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .service(service)
        .boxed_clone()
}

#[derive(Debug, Clone, Default)]
pub struct MakeOtelSpan {
    operation: Option<&'static str>,
    kind: &'static str,
    extract: bool,
}

impl MakeOtelSpan {
    fn client(operation: &'static str) -> Self {
        Self {
            operation: Some(operation),
            extract: false,
            kind: "client",
        }
    }

    fn server() -> Self {
        Self {
            operation: None,
            extract: true,
            kind: "server",
        }
    }
}

impl<B> MakeSpan<B> for MakeOtelSpan {
    fn make_span(&mut self, request: &Request<B>) -> tracing::Span {
        let cx = if self.extract {
            // Extract the context from the headers
            let headers = request.headers();
            let extractor = HeaderExtractor(headers);

            let cx = opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.extract(&extractor)
            });

            if cx.span().span_context().is_remote() {
                cx
            } else {
                opentelemetry::Context::new()
            }
        } else {
            opentelemetry::Context::current()
        };

        // Attach the context so when the request span is created it gets properly
        // parented
        let _guard = cx.attach();

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

        let span = tracing::info_span!(
            "request",
            otel.name = field::Empty,
            otel.kind = self.kind,
            otel.status_code = field::Empty,
            http.method = %request.method(),
            http.target = %request.uri(),
            http.flavor = version,
            http.status_code = field::Empty,
            http.user_agent = field::Empty,
        );

        if let Some(operation) = &self.operation {
            span.record("otel.name", operation);
        }

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
