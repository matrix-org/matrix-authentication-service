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

use std::{sync::Arc, task::Poll, time::SystemTime};

use futures_util::{future::BoxFuture, FutureExt as _};
use opentelemetry::{
    metrics::{Counter, Histogram, UpDownCounter},
    trace::{FutureExt as _, TraceContextExt},
    Context, KeyValue,
};
use tower::Service;

use super::{
    extract_context::ExtractContext, inject_context::InjectContext,
    make_span_builder::MakeSpanBuilder, on_error::OnError, on_response::OnResponse,
};

#[derive(Debug, Clone)]
pub struct Trace<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S> {
    inner: S,
    tracer: Arc<opentelemetry::global::BoxedTracer>,
    extract_context: ExtractContext,
    inject_context: InjectContext,
    make_span_builder: MakeSpanBuilder,
    on_response: OnResponse,
    on_error: OnError,

    inflight_requests: UpDownCounter<i64>,
    request_counter: Counter<u64>,
    request_histogram: Histogram<f64>,
}

impl<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S>
    Trace<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: S,
        tracer: Arc<opentelemetry::global::BoxedTracer>,
        extract_context: ExtractContext,
        inject_context: InjectContext,
        make_span_builder: MakeSpanBuilder,
        on_response: OnResponse,
        on_error: OnError,
        inflight_requests: UpDownCounter<i64>,
        request_counter: Counter<u64>,
        request_histogram: Histogram<f64>,
    ) -> Self {
        Self {
            inner: service,
            tracer,

            extract_context,
            inject_context,
            make_span_builder,
            on_response,
            on_error,

            inflight_requests,
            request_counter,
            request_histogram,
        }
    }
}

struct InFlightGuard {
    context: Context,
    meter: UpDownCounter<i64>,
    attributes: Vec<KeyValue>,
}

impl InFlightGuard {
    fn increment(context: &Context, meter: &UpDownCounter<i64>, attributes: &[KeyValue]) -> Self {
        meter.add(context, 1, attributes);
        Self {
            context: context.clone(),
            meter: meter.clone(),
            attributes: attributes.to_vec(),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.meter.add(&self.context, -1, &self.attributes);
    }
}

impl<Req, S, ExtractContextT, InjectContextT, MakeSpanBuilderT, OnResponseT, OnErrorT> Service<Req>
    for Trace<ExtractContextT, InjectContextT, MakeSpanBuilderT, OnResponseT, OnErrorT, S>
where
    ExtractContextT: ExtractContext<Req> + Send,
    InjectContextT: InjectContext<Req> + Send,
    S: Service<InjectContextT::Output> + Send,
    OnResponseT: OnResponse<S::Response> + Send + Clone + 'static,
    OnErrorT: OnError<S::Error> + Send + Clone + 'static,
    MakeSpanBuilderT: MakeSpanBuilder<Req> + Send,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Req) -> Self::Future {
        let request_counter = self.request_counter.clone();
        let request_histogram = self.request_histogram.clone();
        let start_time = SystemTime::now();

        let cx = self.extract_context.extract_context(&request);
        let (span_builder, mut metrics_labels) = self.make_span_builder.make_span_builder(&request);
        let span = span_builder.start_with_context(self.tracer.as_ref(), &cx);

        let cx = cx.with_span(span);
        let request = self.inject_context.inject_context(&cx, request);

        let guard = InFlightGuard::increment(&cx, &self.inflight_requests, &metrics_labels);

        let on_response = self.on_response.clone();
        let on_error = self.on_error.clone();
        let attachment = cx.clone().attach();
        let ret = self
            .inner
            .call(request)
            .with_context(cx.clone())
            .inspect(move |r| {
                // This ensures the guard gets moved to the future. In case the future panics,
                // it will be dropped anyway, ensuring the in-flight counter stays accurate
                let _guard = guard;

                let span = cx.span();
                let extra_labels = match r {
                    Ok(response) => on_response.on_response(&span, response),
                    Err(err) => on_error.on_error(&span, err),
                };
                metrics_labels.extend_from_slice(&extra_labels);

                request_counter.add(&cx, 1, &metrics_labels);
                request_histogram.record(
                    &cx,
                    start_time.elapsed().map_or(0.0, |d| d.as_secs_f64()),
                    &metrics_labels,
                );

                span.end();
            })
            .boxed();

        drop(attachment);

        ret
    }
}
