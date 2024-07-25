// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

use std::{
    future::ready,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    os::unix::net::UnixListener,
};

use anyhow::Context;
use axum::{
    error_handling::HandleErrorLayer,
    extract::{FromRef, MatchedPath},
    Extension, Router,
};
use hyper::{
    header::{HeaderValue, CACHE_CONTROL, USER_AGENT},
    Method, Request, Response, StatusCode, Version,
};
use listenfd::ListenFd;
use mas_config::{HttpBindConfig, HttpResource, HttpTlsConfig, UnixOrTcp};
use mas_listener::{unix_or_tcp::UnixOrTcpListener, ConnectionInfo};
use mas_router::Route;
use mas_templates::Templates;
use mas_tower::{
    make_span_fn, metrics_attributes_fn, DurationRecorderLayer, InFlightCounterLayer, TraceLayer,
    KV,
};
use opentelemetry::{Key, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::trace::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, NETWORK_PROTOCOL_NAME,
    NETWORK_PROTOCOL_VERSION, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use rustls::ServerConfig;
use sentry_tower::{NewSentryLayer, SentryHttpLayer};
use tower::Layer;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::app_state::AppState;

const MAS_LISTENER_NAME: Key = Key::from_static_str("mas.listener.name");

#[inline]
fn otel_http_method<B>(request: &Request<B>) -> &'static str {
    match request.method() {
        &Method::OPTIONS => "OPTIONS",
        &Method::GET => "GET",
        &Method::POST => "POST",
        &Method::PUT => "PUT",
        &Method::DELETE => "DELETE",
        &Method::HEAD => "HEAD",
        &Method::TRACE => "TRACE",
        &Method::CONNECT => "CONNECT",
        &Method::PATCH => "PATCH",
        _other => "_OTHER",
    }
}

#[inline]
fn otel_net_protocol_version<B>(request: &Request<B>) -> &'static str {
    match request.version() {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _other => "_OTHER",
    }
}

fn otel_http_route<B>(request: &Request<B>) -> Option<&str> {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
}

fn otel_url_scheme<B>(request: &Request<B>) -> &'static str {
    // XXX: maybe we should panic if the connection info was not injected in the
    // request extensions
    request
        .extensions()
        .get::<ConnectionInfo>()
        .map_or("http", |conn_info| {
            if conn_info.get_tls_ref().is_some() {
                "https"
            } else {
                "http"
            }
        })
}

fn make_http_span<B>(req: &Request<B>) -> Span {
    let method = otel_http_method(req);
    let route = otel_http_route(req);

    let span_name = if let Some(route) = route.as_ref() {
        format!("{method} {route}")
    } else {
        method.to_owned()
    };

    let span = tracing::info_span!(
        "http.server.request",
        "otel.kind" = "server",
        "otel.name" = span_name,
        "otel.status_code" = tracing::field::Empty,
        { NETWORK_PROTOCOL_NAME } = "http",
        { NETWORK_PROTOCOL_VERSION } = otel_net_protocol_version(req),
        { HTTP_REQUEST_METHOD } = method,
        { HTTP_ROUTE } = tracing::field::Empty,
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { URL_PATH } = req.uri().path(),
        { URL_QUERY } = tracing::field::Empty,
        { URL_SCHEME } = otel_url_scheme(req),
        { USER_AGENT_ORIGINAL } = tracing::field::Empty,
    );

    if let Some(route) = route.as_ref() {
        span.record(HTTP_ROUTE, route);
    }

    if let Some(query) = req.uri().query() {
        span.record(URL_QUERY, query);
    }

    if let Some(user_agent) = req
        .headers()
        .get(USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
    {
        span.record(USER_AGENT_ORIGINAL, user_agent);
    }

    // Extract the parent span context from the request headers
    let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
        let extractor = HeaderExtractor(req.headers());
        let context = opentelemetry::Context::new();
        propagator.extract_with_context(&context, &extractor)
    });

    span.set_parent(parent_context);

    span
}

fn on_http_request_labels<B>(request: &Request<B>) -> Vec<KeyValue> {
    vec![
        KeyValue::new(NETWORK_PROTOCOL_NAME, "http"),
        KeyValue::new(NETWORK_PROTOCOL_VERSION, otel_net_protocol_version(request)),
        KeyValue::new(HTTP_REQUEST_METHOD, otel_http_method(request)),
        KeyValue::new(
            HTTP_ROUTE,
            otel_http_route(request).unwrap_or("FALLBACK").to_owned(),
        ),
        KeyValue::new(URL_SCHEME, otel_url_scheme(request)),
    ]
}

fn on_http_response_labels<B>(res: &Response<B>) -> Vec<KeyValue> {
    vec![KeyValue::new(
        HTTP_RESPONSE_STATUS_CODE,
        i64::from(res.status().as_u16()),
    )]
}

pub fn build_router(
    state: AppState,
    resources: &[HttpResource],
    prefix: Option<&str>,
    name: Option<&str>,
) -> Router<()> {
    let templates = Templates::from_ref(&state);
    let mut router = Router::new();

    for resource in resources {
        router = match resource {
            mas_config::HttpResource::Health => {
                router.merge(mas_handlers::healthcheck_router::<AppState>())
            }
            mas_config::HttpResource::Prometheus => {
                router.route_service("/metrics", crate::telemetry::prometheus_service())
            }
            mas_config::HttpResource::Discovery => {
                router.merge(mas_handlers::discovery_router::<AppState>())
            }
            mas_config::HttpResource::Human => {
                router.merge(mas_handlers::human_router::<AppState>(templates.clone()))
            }
            mas_config::HttpResource::GraphQL { playground } => {
                router.merge(mas_handlers::graphql_router::<AppState>(*playground))
            }
            mas_config::HttpResource::Assets { path } => {
                let static_service = ServeDir::new(path)
                    .append_index_html_on_directories(false)
                    .precompressed_br()
                    .precompressed_gzip()
                    .precompressed_deflate();

                let error_layer =
                    HandleErrorLayer::new(|_e| ready(StatusCode::INTERNAL_SERVER_ERROR));

                let cache_layer = SetResponseHeaderLayer::overriding(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                );

                router.nest_service(
                    mas_router::StaticAsset::route(),
                    (error_layer, cache_layer).layer(static_service),
                )
            }
            mas_config::HttpResource::OAuth => router.merge(mas_handlers::api_router::<AppState>()),
            mas_config::HttpResource::Compat => {
                router.merge(mas_handlers::compat_router::<AppState>())
            }
            // TODO: do a better handler here
            mas_config::HttpResource::ConnectionInfo => router.route(
                "/connection-info",
                axum::routing::get(|connection: Extension<ConnectionInfo>| async move {
                    format!("{connection:?}")
                }),
            ),
        }
    }

    if let Some(prefix) = prefix {
        let path = format!("{}/", prefix.trim_end_matches('/'));
        router = Router::new().nest(&path, router);
    }

    router = router.fallback(mas_handlers::fallback);

    router
        .layer(
            InFlightCounterLayer::new("http.server.active_requests").on_request((
                name.map(|name| MAS_LISTENER_NAME.string(name.to_owned())),
                metrics_attributes_fn(on_http_request_labels),
            )),
        )
        .layer(
            DurationRecorderLayer::new("http.server.duration")
                .on_request((
                    name.map(|name| MAS_LISTENER_NAME.string(name.to_owned())),
                    metrics_attributes_fn(on_http_request_labels),
                ))
                .on_response_fn(on_http_response_labels),
        )
        .layer(
            TraceLayer::new((
                make_span_fn(make_http_span),
                name.map(|name| KV("mas.listener.name", name.to_owned())),
            ))
            .on_response_fn(|span: &Span, response: &Response<_>| {
                let status_code = response.status().as_u16();
                span.record("http.response.status_code", status_code);
                span.record("otel.status_code", "OK");
            }),
        )
        .layer(SentryHttpLayer::new())
        .layer(NewSentryLayer::new_from_top())
        .with_state(state)
}

pub fn build_tls_server_config(config: &HttpTlsConfig) -> Result<ServerConfig, anyhow::Error> {
    let (key, chain) = config.load()?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("failed to build TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

pub fn build_listeners(
    fd_manager: &mut ListenFd,
    configs: &[HttpBindConfig],
) -> Result<Vec<UnixOrTcpListener>, anyhow::Error> {
    let mut listeners = Vec::with_capacity(configs.len());

    for bind in configs {
        let listener = match bind {
            HttpBindConfig::Listen { host, port } => {
                let addrs = match host.as_deref() {
                    Some(host) => (host, *port)
                        .to_socket_addrs()
                        .context("could not parse listener host")?
                        .collect(),

                    None => vec![
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), *port),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
                    ],
                };

                let listener = TcpListener::bind(&addrs[..]).context("could not bind address")?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            HttpBindConfig::Address { address } => {
                let addr: SocketAddr = address
                    .parse()
                    .context("could not parse listener address")?;
                let listener = TcpListener::bind(addr).context("could not bind address")?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            HttpBindConfig::Unix { socket } => {
                let listener = UnixListener::bind(socket).context("could not bind socket")?;
                listener.try_into()?
            }

            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Tcp,
            } => {
                let listener = fd_manager
                    .take_tcp_listener(*fd)?
                    .context("no listener found on file descriptor")?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Unix,
            } => {
                let listener = fd_manager
                    .take_unix_listener(*fd)?
                    .context("no unix socket found on file descriptor")?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }
        };

        listeners.push(listener);
    }

    Ok(listeners)
}
