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

use http::{header::USER_AGENT, HeaderValue};
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

use super::otel::TraceLayer;
use crate::otel::{TraceHttpClient, TraceHttpClientLayer};

pub type ClientService<S> = SetRequestHeader<
    TraceHttpClient<ConcurrencyLimit<FollowRedirect<TraceHttpClient<Timeout<S>>>>>,
    HeaderValue,
>;

#[derive(Debug, Clone)]
pub struct ClientLayer {
    user_agent_layer: SetRequestHeaderLayer<HeaderValue>,
    outer_trace_layer: TraceHttpClientLayer,
    concurrency_limit_layer: GlobalConcurrencyLimitLayer,
    follow_redirect_layer: FollowRedirectLayer,
    inner_trace_layer: TraceHttpClientLayer,
    timeout_layer: TimeoutLayer,
}

impl ClientLayer {
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        let semaphore = Arc::new(Semaphore::new(10));
        Self::with_semaphore(operation, semaphore)
    }

    #[must_use]
    pub fn with_semaphore(operation: &'static str, semaphore: Arc<Semaphore>) -> Self {
        Self {
            user_agent_layer: SetRequestHeaderLayer::overriding(
                USER_AGENT,
                HeaderValue::from_static("matrix-authentication-service/0.0.1"),
            ),
            outer_trace_layer: TraceLayer::http_client(operation),
            concurrency_limit_layer: GlobalConcurrencyLimitLayer::with_semaphore(semaphore),
            follow_redirect_layer: FollowRedirectLayer::new(),
            inner_trace_layer: TraceLayer::inner_http_client(),
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
            &self.outer_trace_layer,
            &self.concurrency_limit_layer,
            &self.follow_redirect_layer,
            &self.inner_trace_layer,
            &self.timeout_layer,
        )
            .layer(inner)
    }
}
