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

use std::{borrow::Cow, vec::Vec};

#[cfg(feature = "axum")]
use axum::extract::{ConnectInfo, MatchedPath};
use headers::{ContentLength, HeaderMapExt, Host, UserAgent};
use http::{Method, Request, Version};
#[cfg(feature = "client")]
use hyper::client::connect::dns::Name;
use opentelemetry::{
    trace::{SpanBuilder, SpanKind},
    KeyValue,
};
use opentelemetry_semantic_conventions::trace as SC;

pub trait MakeSpanBuilder<R> {
    fn make_span_builder(&self, request: &R) -> (SpanBuilder, Vec<KeyValue>);
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultMakeSpanBuilder {
    operation: &'static str,
}

impl DefaultMakeSpanBuilder {
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        Self { operation }
    }
}

impl Default for DefaultMakeSpanBuilder {
    fn default() -> Self {
        Self {
            operation: "service",
        }
    }
}

impl<R> MakeSpanBuilder<R> for DefaultMakeSpanBuilder {
    fn make_span_builder(&self, _request: &R) -> (SpanBuilder, Vec<KeyValue>) {
        (SpanBuilder::from_name(self.operation), Vec::new())
    }
}

#[inline]
fn http_method_str(method: &Method) -> Cow<'static, str> {
    match method {
        &Method::OPTIONS => "OPTIONS".into(),
        &Method::GET => "GET".into(),
        &Method::POST => "POST".into(),
        &Method::PUT => "PUT".into(),
        &Method::DELETE => "DELETE".into(),
        &Method::HEAD => "HEAD".into(),
        &Method::TRACE => "TRACE".into(),
        &Method::CONNECT => "CONNECT".into(),
        &Method::PATCH => "PATCH".into(),
        other => other.to_string().into(),
    }
}

#[inline]
fn http_flavor(version: Version) -> Cow<'static, str> {
    match version {
        Version::HTTP_09 => "0.9".into(),
        Version::HTTP_10 => "1.0".into(),
        Version::HTTP_11 => "1.1".into(),
        Version::HTTP_2 => "2.0".into(),
        Version::HTTP_3 => "3.0".into(),
        other => format!("{:?}", other).into(),
    }
}

#[derive(Debug, Clone)]
pub struct SpanFromHttpRequest {
    operation: &'static str,
    span_kind: SpanKind,
}

impl SpanFromHttpRequest {
    #[must_use]
    pub fn server() -> Self {
        Self {
            operation: "http-server",
            span_kind: SpanKind::Server,
        }
    }

    #[must_use]
    pub fn inner_client() -> Self {
        Self {
            operation: "http-client",
            span_kind: SpanKind::Client,
        }
    }

    #[must_use]
    pub fn client(operation: &'static str) -> Self {
        Self {
            operation,
            span_kind: SpanKind::Client,
        }
    }
}

impl<B> MakeSpanBuilder<Request<B>> for SpanFromHttpRequest {
    fn make_span_builder(&self, request: &Request<B>) -> (SpanBuilder, Vec<KeyValue>) {
        let method = SC::HTTP_METHOD.string(http_method_str(request.method()));
        let mut attributes = vec![
            method.clone(),
            SC::HTTP_FLAVOR.string(http_flavor(request.version())),
            SC::HTTP_TARGET.string(request.uri().to_string()),
        ];

        let headers = request.headers();

        if let Some(host) = headers.typed_get::<Host>() {
            attributes.push(SC::HTTP_HOST.string(host.to_string()));
        }

        if let Some(user_agent) = headers.typed_get::<UserAgent>() {
            attributes.push(SC::HTTP_USER_AGENT.string(user_agent.to_string()));
        }

        if let Some(ContentLength(content_length)) = headers.typed_get() {
            if let Ok(content_length) = content_length.try_into() {
                attributes.push(SC::HTTP_REQUEST_CONTENT_LENGTH.i64(content_length));
            }
        }

        let span_builder = SpanBuilder::from_name(self.operation)
            .with_kind(self.span_kind.clone())
            .with_attributes(attributes);

        let metrics_labels = vec![method];
        (span_builder, metrics_labels)
    }
}

#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct SpanFromAxumRequest;

#[cfg(feature = "axum")]
impl<B> MakeSpanBuilder<Request<B>> for SpanFromAxumRequest {
    fn make_span_builder(&self, request: &Request<B>) -> (SpanBuilder, Vec<KeyValue>) {
        let method = SC::HTTP_METHOD.string(http_method_str(request.method()));

        let mut metrics_labels = vec![method.clone()];

        let mut attributes = vec![
            method,
            SC::HTTP_FLAVOR.string(http_flavor(request.version())),
            SC::HTTP_TARGET.string(request.uri().to_string()),
        ];

        let headers = request.headers();

        if let Some(host) = headers.typed_get::<Host>() {
            attributes.push(SC::HTTP_HOST.string(host.to_string()));
        }

        if let Some(user_agent) = headers.typed_get::<UserAgent>() {
            attributes.push(SC::HTTP_USER_AGENT.string(user_agent.to_string()));
        }

        if let Some(ContentLength(content_length)) = headers.typed_get() {
            if let Ok(content_length) = content_length.try_into() {
                attributes.push(SC::HTTP_REQUEST_CONTENT_LENGTH.i64(content_length));
            }
        }

        if let Some(ConnectInfo(addr)) = request
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
        {
            attributes.push(SC::NET_TRANSPORT.string("ip_tcp"));
            attributes.push(SC::NET_PEER_IP.string(addr.ip().to_string()));
            attributes.push(SC::NET_PEER_PORT.i64(addr.port().into()));
        }

        let (name, route) = if let Some(path) = request.extensions().get::<MatchedPath>() {
            let path = path.as_str();
            (path, path)
        } else {
            (request.uri().path(), "FALLBACK")
        };

        let route = SC::HTTP_ROUTE.string(route.to_owned());
        attributes.push(route.clone());
        metrics_labels.push(route);

        (
            SpanBuilder::from_name(name.to_owned())
                .with_kind(SpanKind::Server)
                .with_attributes(attributes),
            metrics_labels,
        )
    }
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpanFromDnsRequest;

#[cfg(feature = "client")]
impl MakeSpanBuilder<Name> for SpanFromDnsRequest {
    fn make_span_builder(&self, request: &Name) -> (SpanBuilder, Vec<KeyValue>) {
        let attributes = vec![SC::NET_HOST_NAME.string(request.as_str().to_owned())];

        (
            SpanBuilder::from_name("resolve")
                .with_kind(SpanKind::Client)
                .with_attributes(attributes.clone()),
            attributes,
        )
    }
}
