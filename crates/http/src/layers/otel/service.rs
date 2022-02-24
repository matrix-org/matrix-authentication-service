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

use std::{sync::Arc, task::Poll};

use futures_util::{future::BoxFuture, FutureExt as _};
use opentelemetry::trace::{FutureExt as _, TraceContextExt};
use tower::Service;

use super::{
    extract_context::ExtractContext, inject_context::InjectContext,
    make_span_builder::MakeSpanBuilder, on_error::OnError, on_response::OnResponse,
};

#[derive(Debug, Clone)]
pub struct Trace<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S> {
    pub(crate) inner: S,
    pub(crate) tracer: Arc<opentelemetry::global::BoxedTracer>,
    pub(crate) extract_context: ExtractContext,
    pub(crate) inject_context: InjectContext,
    pub(crate) make_span_builder: MakeSpanBuilder,
    pub(crate) on_response: OnResponse,
    pub(crate) on_error: OnError,
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
        let cx = self.extract_context.extract_context(&request);
        let span_builder = self.make_span_builder.make_span_builder(&request);
        let span = span_builder.start_with_context(self.tracer.as_ref(), &cx);

        let cx = cx.with_span(span);
        let request = self.inject_context.inject_context(&cx, request);

        let on_response = self.on_response.clone();
        let on_error = self.on_error.clone();
        let attachment = cx.clone().attach();
        let ret = self
            .inner
            .call(request)
            .with_context(cx.clone())
            .inspect(move |r| {
                let span = cx.span();
                match r {
                    Ok(response) => on_response.on_response(&span, response),
                    Err(err) => on_error.on_error(&span, err),
                }

                span.end();
            })
            .boxed();

        drop(attachment);

        ret
    }
}
