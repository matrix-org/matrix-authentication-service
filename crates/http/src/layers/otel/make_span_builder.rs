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

#[cfg(feature = "axum")]
use std::borrow::Cow;

#[cfg(feature = "axum")]
use axum::extract::{ConnectInfo, MatchedPath};
use headers::{ContentLength, HeaderMapExt, Host, UserAgent};
use http::Request;
#[cfg(feature = "client")]
use hyper::client::connect::dns::Name;
use opentelemetry::trace::{SpanBuilder, SpanKind};
use opentelemetry_semantic_conventions::trace as SC;

use super::utils::{http_flavor, http_method_str};

pub trait MakeSpanBuilder<R> {
    fn make_span_builder(&self, request: &R) -> SpanBuilder;
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
    fn make_span_builder(&self, _request: &R) -> SpanBuilder {
        SpanBuilder::from_name(self.operation)
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
    fn make_span_builder(&self, request: &Request<B>) -> SpanBuilder {
        let mut attributes = vec![
            SC::HTTP_METHOD.string(http_method_str(request.method())),
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

        SpanBuilder::from_name(self.operation)
            .with_kind(self.span_kind.clone())
            .with_attributes(attributes)
    }
}

#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct SpanFromAxumRequest;

#[cfg(feature = "axum")]
impl<B> MakeSpanBuilder<Request<B>> for SpanFromAxumRequest {
    fn make_span_builder(&self, request: &Request<B>) -> SpanBuilder {
        let (name, route): (String, Cow<'static, str>) =
            if let Some(path) = request.extensions().get::<MatchedPath>() {
                let path = path.as_str().to_owned();
                let name = path.clone();
                (name, path.into())
            } else {
                (request.uri().path().to_owned(), Cow::Borrowed("FALLBACK"))
            };

        let mut attributes = vec![
            SC::HTTP_METHOD.string(http_method_str(request.method())),
            SC::HTTP_FLAVOR.string(http_flavor(request.version())),
            SC::HTTP_TARGET.string(request.uri().to_string()),
            SC::HTTP_ROUTE.string(route),
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

        SpanBuilder::from_name(name)
            .with_kind(SpanKind::Server)
            .with_attributes(attributes)
    }
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpanFromDnsRequest;

#[cfg(feature = "client")]
impl MakeSpanBuilder<Name> for SpanFromDnsRequest {
    fn make_span_builder(&self, request: &Name) -> SpanBuilder {
        let attributes = vec![SC::NET_HOST_NAME.string(request.as_str().to_owned())];

        SpanBuilder::from_name("resolve")
            .with_kind(SpanKind::Client)
            .with_attributes(attributes)
    }
}

#[cfg(feature = "aws-sdk")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SpanFromAwsRequest;

#[cfg(feature = "aws-sdk")]
impl MakeSpanBuilder<aws_smithy_http::operation::Request> for SpanFromAwsRequest {
    fn make_span_builder(&self, request: &aws_smithy_http::operation::Request) -> SpanBuilder {
        let properties = request.properties();
        let request = request.http();
        let mut attributes = vec![
            SC::RPC_SYSTEM.string("aws-api"),
            SC::HTTP_METHOD.string(http_method_str(request.method())),
            SC::HTTP_FLAVOR.string(http_flavor(request.version())),
            SC::HTTP_TARGET.string(request.uri().to_string()),
        ];

        let mut name = Cow::Borrowed("aws_sdk");
        if let Some(metadata) = properties.get::<aws_smithy_http::operation::Metadata>() {
            attributes.push(SC::RPC_SERVICE.string(metadata.service().to_owned()));
            attributes.push(SC::RPC_METHOD.string(metadata.name().to_owned()));
            name = Cow::Owned(metadata.name().to_owned());
        } else if let Some(service) = properties.get::<aws_types::SigningService>() {
            attributes.push(SC::RPC_SERVICE.string(service.as_ref().to_owned()));
        }

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

        SpanBuilder::from_name(name)
            .with_kind(SpanKind::Client)
            .with_attributes(attributes)
    }
}
