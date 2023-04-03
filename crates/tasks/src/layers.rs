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

use std::task::{Context, Poll};

use apalis_core::{job::Job, request::JobRequest};
use mas_storage::job::JobWithSpanContext;
use tower::{Layer, Service};
use tracing::{info_span, instrument::Instrumented, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct TracingLayer;

impl TracingLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for TracingLayer {
    type Service = TracingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TracingService { inner }
    }
}

pub struct TracingService<S> {
    inner: S,
}

impl<J, S> Service<JobRequest<JobWithSpanContext<J>>> for TracingService<S>
where
    J: Job,
    S: Service<JobRequest<JobWithSpanContext<J>>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Instrumented<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: JobRequest<JobWithSpanContext<J>>) -> Self::Future {
        let span = info_span!(
            "job.run",
            job.id = %req.id(),
            job.attempts = req.attempts(),
            job.name = J::NAME,
        );

        if let Some(context) = req.inner().span_context() {
            span.add_link(context);
        }

        self.inner.call(req).instrument(span)
    }
}
