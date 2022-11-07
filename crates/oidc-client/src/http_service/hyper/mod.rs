// Copyright 2022 Kévin Commaille.
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

//! A [`HttpService`] that uses [hyper] as a backend.
//!
//! [hyper]: https://crates.io/crates/hyper

use std::time::Duration;

use http::{header::USER_AGENT, HeaderValue};
use hyper::client::{connect::dns::GaiResolver, HttpConnector};
use hyper_rustls::{ConfigBuilderExt, HttpsConnectorBuilder};
use tower::{limit::ConcurrencyLimitLayer, BoxError, ServiceBuilder};
use tower_http::{
    decompression::DecompressionLayer, follow_redirect::FollowRedirectLayer,
    set_header::SetRequestHeaderLayer, timeout::TimeoutLayer,
};

mod body_layer;

use self::body_layer::BodyLayer;
use super::HttpService;

static MAS_USER_AGENT: HeaderValue = HeaderValue::from_static("mas-oidc-client/0.0.1");

/// Constructs a [`HttpService`] using [hyper] as a backend.
///
/// [hyper]: https://crates.io/crates/hyper
#[must_use]
pub fn hyper_service() -> HttpService {
    let resolver = ServiceBuilder::new().service(GaiResolver::new());

    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    let client = hyper::Client::builder().build(https);

    let client = ServiceBuilder::new()
        .map_err(BoxError::from)
        .layer(BodyLayer::default())
        .layer(DecompressionLayer::new())
        .layer(SetRequestHeaderLayer::overriding(
            USER_AGENT,
            MAS_USER_AGENT.clone(),
        ))
        .layer(ConcurrencyLimitLayer::new(10))
        .layer(FollowRedirectLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .service(client);

    HttpService::new(client)
}
