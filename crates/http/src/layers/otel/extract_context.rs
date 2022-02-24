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

use http::Request;
use opentelemetry::{trace::TraceContextExt, Context};
use opentelemetry_http::HeaderExtractor;

pub trait ExtractContext<R> {
    fn extract_context(&self, request: &R) -> Context;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultExtractContext;

impl<T> ExtractContext<T> for DefaultExtractContext {
    fn extract_context(&self, _request: &T) -> Context {
        Context::current()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractFromHttpRequest;

impl<T> ExtractContext<Request<T>> for ExtractFromHttpRequest {
    fn extract_context(&self, request: &Request<T>) -> Context {
        let headers = request.headers();
        let extractor = HeaderExtractor(headers);
        let parent_cx = Context::current();

        let cx = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract_with_context(&parent_cx, &extractor)
        });

        if cx.span().span_context().is_remote() {
            cx
        } else {
            parent_cx
        }
    }
}
