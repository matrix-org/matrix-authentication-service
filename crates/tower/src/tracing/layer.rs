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

use tower::Layer;
use tracing::Span;

use crate::{enrich_span_fn, make_span_fn, utils::FnWrapper};

#[derive(Clone, Debug)]
pub struct TraceLayer<MakeSpan, OnResponse = (), OnError = ()> {
    make_span: MakeSpan,
    on_response: OnResponse,
    on_error: OnError,
}

impl<F> TraceLayer<FnWrapper<F>> {
    #[must_use]
    pub fn from_fn<T>(f: F) -> TraceLayer<FnWrapper<F>>
    where
        F: Fn(&T) -> Span,
    {
        TraceLayer::new(make_span_fn(f))
    }
}

impl<MakeSpan> TraceLayer<MakeSpan> {
    #[must_use]
    pub fn new(make_span: MakeSpan) -> Self {
        Self {
            make_span,
            on_response: (),
            on_error: (),
        }
    }
}

impl<MakeSpan, OnResponse, OnError> TraceLayer<MakeSpan, OnResponse, OnError> {
    #[must_use]
    pub fn on_response<NewOnResponse>(
        self,
        on_response: NewOnResponse,
    ) -> TraceLayer<MakeSpan, NewOnResponse, OnError> {
        TraceLayer {
            make_span: self.make_span,
            on_response,
            on_error: self.on_error,
        }
    }

    #[must_use]
    pub fn on_response_fn<F, T>(self, f: F) -> TraceLayer<MakeSpan, FnWrapper<F>, OnError>
    where
        F: Fn(&Span, &T),
    {
        self.on_response(enrich_span_fn(f))
    }

    #[must_use]
    pub fn on_error<NewOnError>(
        self,
        on_error: NewOnError,
    ) -> TraceLayer<MakeSpan, OnResponse, NewOnError> {
        TraceLayer {
            make_span: self.make_span,
            on_response: self.on_response,
            on_error,
        }
    }

    pub fn on_error_fn<F, E>(self, f: F) -> TraceLayer<MakeSpan, OnResponse, FnWrapper<F>>
    where
        F: Fn(&Span, &E),
    {
        self.on_error(enrich_span_fn(f))
    }
}

impl<S, MakeSpan, OnResponse, OnError> Layer<S> for TraceLayer<MakeSpan, OnResponse, OnError>
where
    MakeSpan: Clone,
    OnResponse: Clone,
    OnError: Clone,
{
    type Service = super::service::TraceService<S, MakeSpan, OnResponse, OnError>;

    fn layer(&self, inner: S) -> Self::Service {
        super::service::TraceService::new(
            inner,
            self.make_span.clone(),
            self.on_response.clone(),
            self.on_error.clone(),
        )
    }
}
