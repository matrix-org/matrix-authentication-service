// Copyright 2022 Kévin Commaille.
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

use std::task::Poll;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response};
use http_body::{Body, Full};
use hyper::body::to_bytes;
use thiserror::Error;
use tower::{BoxError, Layer, Service};

#[derive(Debug, Error)]
#[error(transparent)]
pub enum BodyError<E> {
    Decompression(BoxError),
    Service(E),
}

#[derive(Clone)]
pub struct BodyService<S> {
    inner: S,
}

impl<S> BodyService<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, E, ResBody> Service<Request<Bytes>> for BodyService<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>, Error = E>,
    ResBody: Body<Data = Bytes, Error = BoxError> + Send,
    S::Future: Send + 'static,
{
    type Error = BodyError<E>;
    type Response = Response<Bytes>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(BodyError::Service)
    }

    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let body = Full::new(body);

        let request = Request::from_parts(parts, body);

        let fut = self.inner.call(request);

        let fut = async {
            let response = fut.await.map_err(BodyError::Service)?;

            let (parts, body) = response.into_parts();
            let body = to_bytes(body).await.map_err(BodyError::Decompression)?;

            let response = Response::from_parts(parts, body);
            Ok(response)
        };

        Box::pin(fut)
    }
}

#[derive(Default, Clone, Copy)]
pub struct BodyLayer(());

impl<S> Layer<S> for BodyLayer {
    type Service = BodyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyService::new(inner)
    }
}
