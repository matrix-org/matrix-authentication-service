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

use http::{header::USER_AGENT, HeaderValue, Request, Response};
use tower::{
    limit::{ConcurrencyLimit, ConcurrencyLimitLayer},
    timeout::{Timeout, TimeoutLayer},
    Layer, Service,
};
use tower_http::{
    decompression::{Decompression, DecompressionBody, DecompressionLayer},
    follow_redirect::{FollowRedirect, FollowRedirectLayer},
    set_header::{SetRequestHeader, SetRequestHeaderLayer},
};

use super::otel::TraceLayer;
use crate::{otel::TraceHttpClient, BoxError};

static MAS_USER_AGENT: HeaderValue =
    HeaderValue::from_static("matrix-authentication-service/0.0.1");

#[derive(Debug, Clone)]
pub struct ClientLayer<ReqBody> {
    operation: &'static str,
    _t: PhantomData<ReqBody>,
}

impl<B> ClientLayer<B> {
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            _t: PhantomData,
        }
    }
}

#[allow(dead_code)]
pub type ClientResponse<B> = Response<DecompressionBody<B>>;

impl<ReqBody, ResBody, S, E> Layer<S> for ClientLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = E>
        + Clone
        + Send
        + Sync
        + 'static,
    ReqBody: http_body::Body + Default + Send + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    S::Future: Send + 'static,
    E: Into<BoxError>,
{
    type Service = Decompression<
        SetRequestHeader<
            TraceHttpClient<ConcurrencyLimit<FollowRedirect<TraceHttpClient<Timeout<S>>>>>,
            HeaderValue,
        >,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        // Note that most layers here just forward the error type. Two notables
        // exceptions are:
        //  - the TimeoutLayer
        //  - the DecompressionLayer
        // Those layers do type erasure of the error.
        (
            DecompressionLayer::new(),
            SetRequestHeaderLayer::overriding(USER_AGENT, MAS_USER_AGENT.clone()),
            // A trace that has the whole operation, with all the redirects, timeouts and rate
            // limits in it
            TraceLayer::http_client(self.operation),
            ConcurrencyLimitLayer::new(10),
            FollowRedirectLayer::new(),
            // A trace for each "real" http request
            TraceLayer::inner_http_client(),
            TimeoutLayer::new(Duration::from_secs(10)),
        )
            .layer(inner)
    }
}
