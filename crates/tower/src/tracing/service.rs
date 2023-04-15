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

use tower::Service;

use super::future::TraceFuture;

#[derive(Clone, Debug)]
pub struct TraceService<S, MakeSpan, OnResponse = (), OnError = ()> {
    inner: S,
    make_span: MakeSpan,
    on_response: OnResponse,
    on_error: OnError,
}

impl<S, MakeSpan, OnResponse, OnError> TraceService<S, MakeSpan, OnResponse, OnError> {
    /// Create a new [`TraceService`].
    #[must_use]
    pub fn new(inner: S, make_span: MakeSpan, on_response: OnResponse, on_error: OnError) -> Self {
        Self {
            inner,
            make_span,
            on_response,
            on_error,
        }
    }
}

impl<R, S, MakeSpan, OnResponse, OnError> Service<R>
    for TraceService<S, MakeSpan, OnResponse, OnError>
where
    S: Service<R>,
    MakeSpan: super::make_span::MakeSpan<R>,
    OnResponse: super::enrich_span::EnrichSpan<S::Response> + Clone,
    OnError: super::enrich_span::EnrichSpan<S::Error> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TraceFuture<S::Future, OnResponse, OnError>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let span = self.make_span.make_span(&request);
        let guard = span.enter();
        let inner = self.inner.call(request);
        drop(guard);

        TraceFuture::new(inner, span, self.on_response.clone(), self.on_error.clone())
    }
}
