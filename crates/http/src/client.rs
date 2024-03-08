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
use tower::Layer;
use tracing::Span;

pub type UntracedClient<B> = hyper::Client<UntracedConnector, B>;
pub type TracedClient<B> = hyper::Client<TracedConnector, B>;

/// Create a basic Hyper HTTP & HTTPS client without any tracing
#[must_use]
pub fn make_untraced_client<B>() -> UntracedClient<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
{
    let https = make_untraced_connector();
    Client::builder().build(https)
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
                "dns.resolve",
                "otel.kind" = "client",
                "net.host.name" = %request,
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
