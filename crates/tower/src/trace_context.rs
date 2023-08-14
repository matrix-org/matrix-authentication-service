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

use http::Request;
use opentelemetry::propagation::Injector;
use opentelemetry_http::HeaderInjector;
use tower::{Layer, Service};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A trait to get an [`Injector`] from a request.
trait AsInjector {
    type Injector<'a>: Injector
    where
        Self: 'a;

    fn as_injector(&mut self) -> Self::Injector<'_>;
}

impl<B> AsInjector for Request<B> {
    type Injector<'a> = HeaderInjector<'a> where Self: 'a;

    fn as_injector(&mut self) -> Self::Injector<'_> {
        HeaderInjector(self.headers_mut())
    }
}

/// A [`Layer`] that adds a trace context to the request.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceContextLayer {
    _private: (),
}

impl TraceContextLayer {
    /// Create a new [`TraceContextLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for TraceContextLayer {
    type Service = TraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceContextService::new(inner)
    }
}

/// A [`Service`] that adds a trace context to the request.
#[derive(Debug, Clone)]
pub struct TraceContextService<S> {
    inner: S,
}

impl<S> TraceContextService<S> {
    /// Create a new [`TraceContextService`].
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, R> Service<R> for TraceContextService<S>
where
    S: Service<R>,
    R: AsInjector,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: R) -> Self::Future {
        // Get the `opentelemetry` context out of the `tracing` span.
        let context = Span::current().context();

        // Inject the trace context into the request. The block is there to ensure that
        // the injector is dropped before calling the inner service, to avoid borrowing
        // issues.
        {
            let mut injector = req.as_injector();
            opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.inject_context(&context, &mut injector);
            });
        }

        self.inner.call(req)
    }
}
