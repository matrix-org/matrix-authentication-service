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

use http::{header::USER_AGENT, Request, Response, Version};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_http::HeaderExtractor;
use tower::Layer;
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{DefaultOnRequest, MakeSpan, OnResponse, Trace},
};
use tracing::{field, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Debug, Clone, Copy)]
pub enum OtelTraceLayer {
    OuterClient(&'static str),
    InnerClient,
    Server,
}

impl OtelTraceLayer {
    pub const fn outer_client(operation: &'static str) -> Self {
        Self::OuterClient(operation)
    }

    pub const fn inner_client() -> Self {
        Self::InnerClient
    }

    pub const fn server() -> Self {
        Self::Server
    }
}

impl<S> Layer<S> for OtelTraceLayer {
    type Service = Trace<
        S,
        SharedClassifier<ServerErrorsAsFailures>,
        MakeOtelSpan,
        DefaultOnRequest,
        OtelOnResponse,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        let make_span = match self {
            Self::OuterClient(o) => MakeOtelSpan::OuterClient(o),
            Self::InnerClient => MakeOtelSpan::InnerClient,
            Self::Server => MakeOtelSpan::Server,
        };

        Trace::new_for_http(inner)
            .make_span_with(make_span)
            .on_response(OtelOnResponse)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MakeOtelSpan {
    OuterClient(&'static str),
    InnerClient,
    Server,
}

impl<B> MakeSpan<B> for MakeOtelSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
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
    fn on_response(self, response: &Response<B>, _latency: Duration, span: &Span) {
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
