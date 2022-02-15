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

use http::{Request, Uri};
use tower::{Layer, Service};

pub struct Get<S> {
    inner: S,
}

impl<S> Get<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Service<Uri> for Get<S>
where
    S: Service<Request<http_body::Empty<()>>>,
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

    fn call(&mut self, req: Uri) -> Self::Future {
        let body = http_body::Empty::new();
        let req = Request::builder()
            .method("GET")
            .uri(req)
            .body(body)
            .unwrap();
        self.inner.call(req)
    }
}

#[derive(Default, Clone, Copy)]
pub struct GetLayer;

impl<S> Layer<S> for GetLayer
where
    S: Service<Request<http_body::Empty<()>>>,
{
    type Service = Get<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Get::new(inner)
    }
}
