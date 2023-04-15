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

use std::{sync::Arc, time::Duration};

use http::{header::USER_AGENT, HeaderValue, Request};
use mas_tower::{MakeSpan, TraceContextLayer, TraceContextService, TraceLayer, TraceService};
use tokio::sync::Semaphore;
use tower::{
    limit::{ConcurrencyLimit, GlobalConcurrencyLimitLayer},
    Layer,
};
use tower_http::{
    follow_redirect::{FollowRedirect, FollowRedirectLayer},
    set_header::{SetRequestHeader, SetRequestHeaderLayer},
    timeout::{Timeout, TimeoutLayer},
};

pub type ClientService<S> = SetRequestHeader<
    ConcurrencyLimit<
        FollowRedirect<TraceService<TraceContextService<Timeout<S>>, MakeSpanForRequest>>,
    >,
    HeaderValue,
>;

#[derive(Debug, Clone)]
pub struct MakeSpanForRequest;

impl<B> MakeSpan<Request<B>> for MakeSpanForRequest {
    fn make_span(&self, request: &Request<B>) -> tracing::Span {
        // TODO: better attributes
        tracing::info_span!(
            "http.client.request",
            "http.method" = %request.method(),
            "http.uri" = %request.uri(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ClientLayer {
    user_agent_layer: SetRequestHeaderLayer<HeaderValue>,
    concurrency_limit_layer: GlobalConcurrencyLimitLayer,
    follow_redirect_layer: FollowRedirectLayer,
    trace_layer: TraceLayer<MakeSpanForRequest>,
    trace_context_layer: TraceContextLayer,
    timeout_layer: TimeoutLayer,
}

impl Default for ClientLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientLayer {
    #[must_use]
    pub fn new() -> Self {
        let semaphore = Arc::new(Semaphore::new(10));
        Self::with_semaphore(semaphore)
    }

    #[must_use]
    pub fn with_semaphore(semaphore: Arc<Semaphore>) -> Self {
        Self {
            user_agent_layer: SetRequestHeaderLayer::overriding(
                USER_AGENT,
                HeaderValue::from_static("matrix-authentication-service/0.0.1"),
            ),
            concurrency_limit_layer: GlobalConcurrencyLimitLayer::with_semaphore(semaphore),
            follow_redirect_layer: FollowRedirectLayer::new(),
            trace_layer: TraceLayer::new(MakeSpanForRequest),
            trace_context_layer: TraceContextLayer::new(),
            timeout_layer: TimeoutLayer::new(Duration::from_secs(10)),
        }
    }
}

impl<S> Layer<S> for ClientLayer
where
    S: Clone,
{
    type Service = ClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        (
            &self.user_agent_layer,
            &self.concurrency_limit_layer,
            &self.follow_redirect_layer,
            &self.trace_layer,
            &self.trace_context_layer,
            &self.timeout_layer,
        )
            .layer(inner)
    }
}
