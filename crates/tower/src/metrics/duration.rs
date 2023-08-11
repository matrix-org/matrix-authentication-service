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

use opentelemetry::{metrics::Histogram, KeyValue};
use pin_project_lite::pin_project;
use tokio::time::Instant;
use tower::{Layer, Service};

use crate::{utils::FnWrapper, MetricsAttributes};

/// A [`Layer`] that records the duration of requests in milliseconds.
#[derive(Clone, Debug)]
pub struct DurationRecorderLayer<OnRequest = (), OnResponse = (), OnError = ()> {
    histogram: Histogram<u64>,
    on_request: OnRequest,
    on_response: OnResponse,
    on_error: OnError,
}

impl DurationRecorderLayer {
    /// Create a new [`DurationRecorderLayer`].
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        let histogram = crate::meter().u64_histogram(name).init();
        Self {
            histogram,
            on_request: (),
            on_response: (),
            on_error: (),
        }
    }
}

impl<OnRequest, OnResponse, OnError> DurationRecorderLayer<OnRequest, OnResponse, OnError> {
    /// Set the [`MetricsAttributes`] to use on request.
    #[must_use]
    pub fn on_request<NewOnRequest>(
        self,
        on_request: NewOnRequest,
    ) -> DurationRecorderLayer<NewOnRequest, OnResponse, OnError> {
        DurationRecorderLayer {
            histogram: self.histogram,
            on_request,
            on_response: self.on_response,
            on_error: self.on_error,
        }
    }

    #[must_use]
    pub fn on_request_fn<F, T>(
        self,
        on_request: F,
    ) -> DurationRecorderLayer<FnWrapper<F>, OnResponse, OnError>
    where
        F: Fn(&T) -> Vec<KeyValue>,
    {
        self.on_request(FnWrapper(on_request))
    }

    /// Set the [`MetricsAttributes`] to use on response.
    #[must_use]
    pub fn on_response<NewOnResponse>(
        self,
        on_response: NewOnResponse,
    ) -> DurationRecorderLayer<OnRequest, NewOnResponse, OnError> {
        DurationRecorderLayer {
            histogram: self.histogram,
            on_request: self.on_request,
            on_response,
            on_error: self.on_error,
        }
    }

    #[must_use]
    pub fn on_response_fn<F, T>(
        self,
        on_response: F,
    ) -> DurationRecorderLayer<OnRequest, FnWrapper<F>, OnError>
    where
        F: Fn(&T) -> Vec<KeyValue>,
    {
        self.on_response(FnWrapper(on_response))
    }

    /// Set the [`MetricsAttributes`] to use on error.
    #[must_use]
    pub fn on_error<NewOnError>(
        self,
        on_error: NewOnError,
    ) -> DurationRecorderLayer<OnRequest, OnResponse, NewOnError> {
        DurationRecorderLayer {
            histogram: self.histogram,
            on_request: self.on_request,
            on_response: self.on_response,
            on_error,
        }
    }

    #[must_use]
    pub fn on_error_fn<F, T>(
        self,
        on_error: F,
    ) -> DurationRecorderLayer<OnRequest, OnResponse, FnWrapper<F>>
    where
        F: Fn(&T) -> Vec<KeyValue>,
    {
        self.on_error(FnWrapper(on_error))
    }
}

impl<S, OnRequest, OnResponse, OnError> Layer<S>
    for DurationRecorderLayer<OnRequest, OnResponse, OnError>
where
    OnRequest: Clone,
    OnResponse: Clone,
    OnError: Clone,
{
    type Service = DurationRecorderService<S, OnRequest, OnResponse, OnError>;

    fn layer(&self, inner: S) -> Self::Service {
        DurationRecorderService {
            inner,
            histogram: self.histogram.clone(),
            on_request: self.on_request.clone(),
            on_response: self.on_response.clone(),
            on_error: self.on_error.clone(),
        }
    }
}

/// A middleware that records the duration of requests in milliseconds.
#[derive(Clone, Debug)]
pub struct DurationRecorderService<S, OnRequest = (), OnResponse = (), OnError = ()> {
    inner: S,
    histogram: Histogram<u64>,
    on_request: OnRequest,
    on_response: OnResponse,
    on_error: OnError,
}

pin_project! {
    /// The future returned by the [`DurationRecorderService`].
    pub struct DurationRecorderFuture<F, OnResponse = (), OnError = ()> {
        #[pin]
        inner: F,

        start: Instant,
        histogram: Histogram<u64>,
        attributes_from_request: Vec<KeyValue>,
        from_response: OnResponse,
        from_error: OnError,
    }
}

impl<F, R, E, OnResponse, OnError> Future for DurationRecorderFuture<F, OnResponse, OnError>
where
    F: Future<Output = Result<R, E>>,
    OnResponse: MetricsAttributes<R>,
    OnError: MetricsAttributes<E>,
{
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.inner.poll(cx));

        // Measure the duration of the request.
        let duration = this.start.elapsed();
        let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);

        // Collect the attributes from the request, response and error.
        let mut attributes = this.attributes_from_request.clone();
        match &result {
            Ok(response) => {
                attributes.extend(this.from_response.attributes(response));
            }
            Err(error) => {
                attributes.extend(this.from_error.attributes(error));
            }
        }

        this.histogram.record(duration_ms, &attributes);
        std::task::Poll::Ready(result)
    }
}

impl<S, R, OnRequest, OnResponse, OnError> Service<R>
    for DurationRecorderService<S, OnRequest, OnResponse, OnError>
where
    S: Service<R>,
    OnRequest: MetricsAttributes<R>,
    OnResponse: MetricsAttributes<S::Response> + Clone,
    OnError: MetricsAttributes<S::Error> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = DurationRecorderFuture<S::Future, OnResponse, OnError>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let start = Instant::now();
        let attributes_from_request = self.on_request.attributes(&request).collect();
        let inner = self.inner.call(request);

        DurationRecorderFuture {
            inner,
            start,
            histogram: self.histogram.clone(),
            attributes_from_request,
            from_response: self.on_response.clone(),
            from_error: self.on_error.clone(),
        }
    }
}
