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

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct BytesToBodyRequest<S> {
    inner: S,
}

impl<S> BytesToBodyRequest<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Service<Request<Bytes>> for BytesToBodyRequest<S>
where
    S: Service<Request<Full<Bytes>>>,
    S::Future: Send + 'static,
{
    type Error = S::Error;
    type Response = S::Response;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let body = Full::new(body);

        let request = Request::from_parts(parts, body);

        self.inner.call(request)
    }
}

#[derive(Default, Clone, Copy)]
pub struct BytesToBodyRequestLayer;

impl<S> Layer<S> for BytesToBodyRequestLayer {
    type Service = BytesToBodyRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BytesToBodyRequest::new(inner)
    }
}
