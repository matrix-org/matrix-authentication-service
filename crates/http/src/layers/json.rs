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

use std::{marker::PhantomData, task::Poll};

use futures_util::future::BoxFuture;
use http::{header::ACCEPT, HeaderValue, Request, Response};
use http_body::Body;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<Service, Body> {
    #[error(transparent)]
    Service { inner: Service },

    #[error("failed to fully read the request body")]
    Body {
        #[source]
        inner: Body,
    },

    #[error("could not parse JSON payload")]
    Json {
        #[source]
        inner: serde_json::Error,
    },
}

impl<S, B> Error<S, B> {
    fn service(source: S) -> Self {
        Self::Service { inner: source }
    }

    fn body(source: B) -> Self {
        Self::Body { inner: source }
    }

    fn json(source: serde_json::Error) -> Self {
        Self::Json { inner: source }
    }
}

#[derive(Clone)]
pub struct Json<S, T> {
    inner: S,
    _t: PhantomData<T>,
}

impl<S, T> Json<S, T> {
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _t: PhantomData,
        }
    }
}

impl<S, T, B, C> Service<Request<B>> for Json<S, T>
where
    S: Service<Request<B>, Response = Response<C>>,
    S::Future: Send + 'static,
    C: Body + Send + 'static,
    C::Data: Send + 'static,
    T: DeserializeOwned,
{
    type Error = Error<S::Error, C::Error>;
    type Response = Response<T>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("application/json"));

        let fut = self.inner.call(request);

        let fut = async {
            let response = fut.await.map_err(Error::service)?;
            let (parts, body) = response.into_parts();

            futures_util::pin_mut!(body);
            let bytes = hyper::body::to_bytes(&mut body)
                .await
                .map_err(Error::body)?;

            let body = serde_json::from_slice(&bytes.to_vec()).map_err(Error::json)?;

            let res = Response::from_parts(parts, body);
            Ok(res)
        };

        Box::pin(fut)
    }
}

#[derive(Default, Clone, Copy)]
pub struct JsonResponseLayer<T, ReqBody>(PhantomData<(T, ReqBody)>);

impl<ReqBody, ResBody, S, T> Layer<S> for JsonResponseLayer<T, ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    T: serde::de::DeserializeOwned,
{
    type Service = Json<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        Json::new(inner)
    }
}
