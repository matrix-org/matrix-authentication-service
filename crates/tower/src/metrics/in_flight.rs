// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::future::Future;

use opentelemetry::{metrics::UpDownCounter, KeyValue};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::MetricsAttributes;

/// A [`Layer`] that records the number of in-flight requests.
///
/// # Generic Parameters
///
/// * `OnRequest`: A type that can extract attributes from a request.
#[derive(Clone, Debug)]
pub struct InFlightCounterLayer<OnRequest = ()> {
    counter: UpDownCounter<i64>,
    on_request: OnRequest,
}

impl InFlightCounterLayer {
    /// Create a new [`InFlightCounterLayer`].
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        let counter = crate::meter()
            .i64_up_down_counter(name)
            .with_unit("{request}")
            .with_description("The number of in-flight requests")
            .init();

        Self {
            counter,
            on_request: (),
        }
    }
}

impl<F> InFlightCounterLayer<F> {
    /// Set the [`MetricsAttributes`] to use.
    #[must_use]
    pub fn on_request<OnRequest>(self, on_request: OnRequest) -> InFlightCounterLayer<OnRequest> {
        InFlightCounterLayer {
            counter: self.counter,
            on_request,
        }
    }
}

impl<S, OnRequest> Layer<S> for InFlightCounterLayer<OnRequest>
where
    OnRequest: Clone,
{
    type Service = InFlightCounterService<S, OnRequest>;

    fn layer(&self, inner: S) -> Self::Service {
        InFlightCounterService {
            inner,
            counter: self.counter.clone(),
            on_request: self.on_request.clone(),
        }
    }
}

/// A middleware that records the number of in-flight requests.
///
/// # Generic Parameters
///
/// * `S`: The type of the inner service.
/// * `OnRequest`: A type that can extract attributes from a request.
#[derive(Clone, Debug)]
pub struct InFlightCounterService<S, OnRequest = ()> {
    inner: S,
    counter: UpDownCounter<i64>,
    on_request: OnRequest,
}

/// A guard that decrements the in-flight request count when dropped.
struct InFlightGuard {
    counter: UpDownCounter<i64>,
    attributes: Vec<KeyValue>,
}

impl InFlightGuard {
    fn new(counter: UpDownCounter<i64>, attributes: Vec<KeyValue>) -> Self {
        counter.add(1, &attributes);

        Self {
            counter,
            attributes,
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.add(-1, &self.attributes);
    }
}

pin_project! {
    /// The future returned by [`InFlightCounterService`]
    pub struct InFlightFuture<F> {
        guard: InFlightGuard,

        #[pin]
        inner: F,
    }
}

impl<F> Future for InFlightFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl<R, S, OnRequest> Service<R> for InFlightCounterService<S, OnRequest>
where
    S: Service<R>,
    OnRequest: MetricsAttributes<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = InFlightFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        // Extract attributes from the request.
        let attributes = self.on_request.attributes(&req).collect();

        // Increment the in-flight request count.
        let guard = InFlightGuard::new(self.counter.clone(), attributes);

        // Call the inner service, and return a future that decrements the in-flight
        // when dropped.
        let inner = self.inner.call(req);
        InFlightFuture { guard, inner }
    }
}
