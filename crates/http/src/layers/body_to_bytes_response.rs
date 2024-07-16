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
use futures_util::future::BoxFuture;
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<ServiceError, BodyError> {
    #[error(transparent)]
    Service { inner: ServiceError },

    #[error(transparent)]
    Body { inner: BodyError },
}

impl<S, B> Error<S, B> {
    fn service(inner: S) -> Self {
        Self::Service { inner }
    }

    fn body(inner: B) -> Self {
        Self::Body { inner }
    }
}

impl<E> Error<E, E> {
    pub fn unify(self) -> E {
        match self {
            Self::Service { inner } | Self::Body { inner } => inner,
        }
    }
}

#[derive(Clone)]
pub struct BodyToBytesResponse<S> {
    inner: S,
}

impl<S> BodyToBytesResponse<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for BodyToBytesResponse<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: Body + Send,
    ResBody::Data: Send,
{
    type Error = Error<S::Error, ResBody::Error>;
    type Response = Response<Bytes>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.call(request);

        let fut = async {
            let response = inner.await.map_err(Error::service)?;
            let (parts, body) = response.into_parts();

            let body = body.collect().await.map_err(Error::body)?.to_bytes();

            let response = Response::from_parts(parts, body);
            Ok(response)
        };

        Box::pin(fut)
    }
}

#[derive(Default, Clone, Copy)]
pub struct BodyToBytesResponseLayer;

impl<S> Layer<S> for BodyToBytesResponseLayer {
    type Service = BodyToBytesResponse<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyToBytesResponse::new(inner)
    }
}
