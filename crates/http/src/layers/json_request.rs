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

use std::{future::Ready, marker::PhantomData, task::Poll};

use bytes::Bytes;
use futures_util::{
    future::{Either, MapErr},
    FutureExt, TryFutureExt,
};
use headers::{ContentType, HeaderMapExt};
use http::Request;
use serde::Serialize;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<Service> {
    #[error(transparent)]
    Service { inner: Service },

    #[error("could not serialize JSON payload")]
    Serialize {
        #[source]
        inner: serde_json::Error,
    },
}

impl<S> Error<S> {
    fn service(source: S) -> Self {
        Self::Service { inner: source }
    }

    fn serialize(source: serde_json::Error) -> Self {
        Self::Serialize { inner: source }
    }
}

#[derive(Clone)]
pub struct JsonRequest<S, T> {
    inner: S,
    _t: PhantomData<T>,
}

impl<S, T> JsonRequest<S, T> {
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _t: PhantomData,
        }
    }
}

impl<S, T> Service<Request<T>> for JsonRequest<S, T>
where
    S: Service<Request<Bytes>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    T: Serialize,
{
    type Error = Error<S::Error>;
    type Response = S::Response;
    type Future = Either<
        Ready<Result<Self::Response, Self::Error>>,
        MapErr<S::Future, fn(S::Error) -> Self::Error>,
    >;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<T>) -> Self::Future {
        let (mut parts, body) = request.into_parts();

        parts.headers.typed_insert(ContentType::json());

        let body = match serde_json::to_vec(&body) {
            Ok(body) => Bytes::from(body),
            Err(err) => return std::future::ready(Err(Error::serialize(err))).left_future(),
        };

        let request = Request::from_parts(parts, body);

        self.inner
            .call(request)
            .map_err(Error::service as fn(S::Error) -> Self::Error)
            .right_future()
    }
}

#[derive(Clone, Copy)]
pub struct JsonRequestLayer<T> {
    _t: PhantomData<T>,
}

impl<T> Default for JsonRequestLayer<T> {
    fn default() -> Self {
        Self {
            _t: PhantomData::default(),
        }
    }
}

impl<S, T> Layer<S> for JsonRequestLayer<T> {
    type Service = JsonRequest<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRequest::new(inner)
    }
}
