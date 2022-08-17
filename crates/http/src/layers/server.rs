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

use std::marker::PhantomData;

use http::{Request, Response};
use tower::{util::BoxCloneService, Layer, Service, ServiceBuilder, ServiceExt};
use tower_http::{compression::CompressionBody, ServiceBuilderExt};

use super::otel::TraceLayer;

#[derive(Debug, Default)]
pub struct ServerLayer<ReqBody> {
    _t: PhantomData<ReqBody>,
}

impl<ReqBody, ResBody, S> Layer<S> for ServerLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display,
    ReqBody: http_body::Body + 'static,
    ResBody: http_body::Body + Send + 'static,
{
    #[allow(clippy::type_complexity)]
    type Service = BoxCloneService<Request<ReqBody>, Response<CompressionBody<ResBody>>, S::Error>;

    fn layer(&self, inner: S) -> Self::Service {
        let builder = ServiceBuilder::new().compression();

        #[cfg(feature = "axum")]
        let builder = builder.layer(TraceLayer::axum());

        #[cfg(not(feature = "axum"))]
        let builder = builder.layer(TraceLayer::http_server());

        builder.service(inner).boxed_clone()
    }
}
