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

use std::{marker::PhantomData, time::Duration};

use http::{Request, Response};
use http_body::combinators::BoxBody;
use tower::{
    timeout::TimeoutLayer, util::BoxCloneService, Layer, Service, ServiceBuilder, ServiceExt,
};
use tower_http::compression::{CompressionBody, CompressionLayer};

use super::trace::OtelTraceLayer;
use crate::BoxError;

#[derive(Debug, Default)]
pub struct ServerLayer<ReqBody> {
    _t: PhantomData<ReqBody>,
}

impl<ReqBody, ResBody, S, E> Layer<S> for ServerLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = E> + Clone + Send + 'static,
    ReqBody: http_body::Body + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    ResBody::Error: std::fmt::Display + 'static,
    S::Future: Send + 'static,
    E: Into<BoxError>,
{
    #[allow(clippy::type_complexity)]
    type Service = BoxCloneService<
        Request<ReqBody>,
        Response<CompressionBody<BoxBody<ResBody::Data, ResBody::Error>>>,
        BoxError,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .map_response(|r: Response<_>| r.map(BoxBody::new))
            .layer(OtelTraceLayer::server())
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
            .service(inner)
            .boxed_clone()
    }
}
