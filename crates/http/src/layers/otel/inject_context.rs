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
use opentelemetry::Context;
use opentelemetry_http::HeaderInjector;

pub trait InjectContext<R> {
    type Output;

    fn inject_context(&self, cx: &Context, request: R) -> Self::Output;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultInjectContext;

impl<R> InjectContext<R> for DefaultInjectContext {
    type Output = R;

    fn inject_context(&self, _cx: &Context, request: R) -> Self::Output {
        request
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InjectInHttpRequest;

impl<T> InjectContext<Request<T>> for InjectInHttpRequest {
    type Output = Request<T>;

    fn inject_context(&self, cx: &Context, mut request: Request<T>) -> Self::Output {
        let headers = request.headers_mut();
        let mut injector = HeaderInjector(headers);

        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(cx, &mut injector);
        });

        request
    }
}
