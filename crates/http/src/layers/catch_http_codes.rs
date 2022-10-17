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

use std::ops::{Bound, RangeBounds};

use futures_util::FutureExt;
use http::{Request, Response, StatusCode};
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<S, E> {
    #[error(transparent)]
    Service { inner: S },

    #[error("request failed with status {status_code}")]
    HttpError {
        status_code: StatusCode,
        #[source]
        inner: E,
    },
}

impl<S, E> Error<S, E> {
    fn service(inner: S) -> Self {
        Self::Service { inner }
    }

    pub fn status_code(&self) -> Option<StatusCode> {
        match self {
            Self::Service { .. } => None,
            Self::HttpError { status_code, .. } => Some(*status_code),
        }
    }
}

#[derive(Clone)]
pub struct CatchHttpCodes<S, M> {
    inner: S,
    bounds: (Bound<StatusCode>, Bound<StatusCode>),
    mapper: M,
}

impl<S, M> CatchHttpCodes<S, M> {
    pub fn new<B>(inner: S, bounds: B, mapper: M) -> Self
    where
        B: RangeBounds<StatusCode>,
        M: Clone,
    {
        let bounds = (bounds.start_bound().cloned(), bounds.end_bound().cloned());
        Self {
            inner,
            bounds,
            mapper,
        }
    }
}

impl<S, M, E, ReqBody, ResBody> Service<Request<ReqBody>> for CatchHttpCodes<S, M>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    M: Fn(Response<ResBody>) -> E + Send + Clone + 'static,
{
    type Error = Error<S::Error, E>;
    type Response = Response<ResBody>;
    type Future = futures_util::future::Map<
        S::Future,
        Box<
            dyn Fn(Result<S::Response, S::Error>) -> Result<Self::Response, Self::Error>
                + Send
                + 'static,
        >,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let fut = self.inner.call(request);
        let bounds = self.bounds;
        let mapper = self.mapper.clone();

        fut.map(Box::new(move |res: Result<S::Response, S::Error>| {
            let response = res.map_err(Error::service)?;
            let status_code = response.status();

            if bounds.contains(&status_code) {
                let inner = mapper(response);
                Err(Error::HttpError { status_code, inner })
            } else {
                Ok(response)
            }
        }))
    }
}

#[derive(Clone)]
pub struct CatchHttpCodesLayer<M> {
    bounds: (Bound<StatusCode>, Bound<StatusCode>),
    mapper: M,
}

impl<M> CatchHttpCodesLayer<M> {
    pub fn new<B>(bounds: B, mapper: M) -> Self
    where
        B: RangeBounds<StatusCode>,
        M: Clone,
    {
        let bounds = (bounds.start_bound().cloned(), bounds.end_bound().cloned());
        Self { bounds, mapper }
    }
}

impl<S, M> Layer<S> for CatchHttpCodesLayer<M>
where
    M: Clone,
{
    type Service = CatchHttpCodes<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        CatchHttpCodes::new(inner, self.bounds, self.mapper.clone())
    }
}
