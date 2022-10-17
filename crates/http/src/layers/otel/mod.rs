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

mod extract_context;
mod inject_context;
mod layer;
mod make_metrics_labels;
mod make_span_builder;
mod on_error;
mod on_response;
mod service;
mod utils;

pub type TraceHttpServerLayer = TraceLayer<
    ExtractFromHttpRequest,
    DefaultInjectContext,
    SpanFromHttpRequest,
    MetricsLabelsFromHttpRequest,
    OnHttpResponse,
    DefaultOnError,
>;

pub type TraceHttpServer<S> = Trace<
    ExtractFromHttpRequest,
    DefaultInjectContext,
    SpanFromHttpRequest,
    MetricsLabelsFromHttpRequest,
    OnHttpResponse,
    DefaultOnError,
    S,
>;

#[cfg(feature = "axum")]
pub type TraceAxumServerLayer = TraceLayer<
    ExtractFromHttpRequest,
    DefaultInjectContext,
    SpanFromAxumRequest,
    MetricsLabelsFromAxumRequest,
    OnHttpResponse,
    DefaultOnError,
>;

#[cfg(feature = "axum")]
pub type TraceAxumServer<S> = Trace<
    ExtractFromHttpRequest,
    DefaultInjectContext,
    SpanFromAxumRequest,
    MetricsLabelsFromAxumRequest,
    OnHttpResponse,
    DefaultOnError,
    S,
>;

pub type TraceHttpClientLayer = TraceLayer<
    DefaultExtractContext,
    InjectInHttpRequest,
    SpanFromHttpRequest,
    MetricsLabelsFromHttpRequest,
    OnHttpResponse,
    DefaultOnError,
>;

pub type TraceHttpClient<S> = Trace<
    DefaultExtractContext,
    InjectInHttpRequest,
    SpanFromHttpRequest,
    MetricsLabelsFromHttpRequest,
    OnHttpResponse,
    DefaultOnError,
    S,
>;

#[cfg(feature = "client")]
pub type TraceDnsLayer = TraceLayer<
    DefaultExtractContext,
    DefaultInjectContext,
    SpanFromDnsRequest,
    DefaultMakeMetricsLabels,
    DefaultOnResponse,
    DefaultOnError,
>;

#[cfg(feature = "client")]
pub type TraceDns<S> = Trace<
    DefaultExtractContext,
    DefaultInjectContext,
    SpanFromDnsRequest,
    DefaultMakeMetricsLabels,
    DefaultOnResponse,
    DefaultOnError,
    S,
>;

impl TraceHttpServerLayer {
    #[must_use]
    pub fn http_server() -> Self {
        TraceLayer::with_namespace("http_server")
            .make_span_builder(SpanFromHttpRequest::server())
            .make_metrics_labels(MetricsLabelsFromHttpRequest::default())
            .on_response(OnHttpResponse)
            .extract_context(ExtractFromHttpRequest)
    }
}

#[cfg(feature = "axum")]
impl TraceAxumServerLayer {
    #[must_use]
    pub fn axum() -> Self {
        TraceLayer::with_namespace("http_server")
            .make_span_builder(SpanFromAxumRequest)
            .make_metrics_labels(MetricsLabelsFromAxumRequest::default())
            .on_response(OnHttpResponse)
            .extract_context(ExtractFromHttpRequest)
    }
}

impl TraceHttpClientLayer {
    #[must_use]
    pub fn http_client(operation: &'static str) -> Self {
        TraceLayer::with_namespace("http_client")
            .make_span_builder(SpanFromHttpRequest::client(operation))
            .make_metrics_labels(MetricsLabelsFromHttpRequest::default())
            .on_response(OnHttpResponse)
            .inject_context(InjectInHttpRequest)
    }

    #[must_use]
    pub fn inner_http_client() -> Self {
        TraceLayer::with_namespace("inner_http_client")
            .make_span_builder(SpanFromHttpRequest::inner_client())
            .make_metrics_labels(MetricsLabelsFromHttpRequest::default())
            .on_response(OnHttpResponse)
            .inject_context(InjectInHttpRequest)
    }
}

#[cfg(feature = "client")]
impl TraceDnsLayer {
    #[must_use]
    pub fn dns() -> Self {
        TraceLayer::with_namespace("dns").make_span_builder(SpanFromDnsRequest)
    }
}

#[cfg(feature = "client")]
use self::make_metrics_labels::DefaultMakeMetricsLabels;
#[cfg(feature = "axum")]
use self::make_metrics_labels::MetricsLabelsFromAxumRequest;
use self::make_metrics_labels::MetricsLabelsFromHttpRequest;
pub use self::{
    extract_context::*, inject_context::*, layer::*, make_span_builder::*, on_error::*,
    on_response::*, service::*,
};
