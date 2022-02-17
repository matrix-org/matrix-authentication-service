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

use http::{header::USER_AGENT, HeaderValue, Request, Response};
use http_body::combinators::BoxBody;
use tower::{
    limit::ConcurrencyLimitLayer, timeout::TimeoutLayer, util::BoxCloneService, Layer, Service,
    ServiceBuilder, ServiceExt,
};
use tower_http::{
    decompression::{DecompressionBody, DecompressionLayer},
    follow_redirect::FollowRedirectLayer,
    set_header::SetRequestHeaderLayer,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::trace::OtelTraceLayer;

static MAS_USER_AGENT: HeaderValue =
    HeaderValue::from_static("matrix-authentication-service/0.0.1");

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct ClientLayer<ReqBody> {
    operation: &'static str,
    _t: PhantomData<ReqBody>,
}

impl<B> ClientLayer<B> {
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            _t: PhantomData,
        }
    }
}

pub type ClientResponse<B> = Response<
    DecompressionBody<BoxBody<<B as http_body::Body>::Data, <B as http_body::Body>::Error>>,
>;

impl<ReqBody, ResBody, S, E> Layer<S> for ClientLayer<ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = E> + Clone + Send + 'static,
    ReqBody: http_body::Body + Default + Send + 'static,
    ResBody: http_body::Body + Sync + Send + 'static,
    ResBody::Error: std::fmt::Display + 'static,
    S::Future: Send + 'static,
    E: Into<BoxError>,
{
    type Service = BoxCloneService<Request<ReqBody>, ClientResponse<ResBody>, BoxError>;

    fn layer(&self, inner: S) -> Self::Service {
        // Note that most layers here just forward the error type. Two notables
        // exceptions are:
        //  - the TimeoutLayer
        //  - the DecompressionLayer
        // Those layers do type erasure of the error.
        // The body is also type-erased because of the DecompressionLayer.

        ServiceBuilder::new()
            .layer(DecompressionLayer::new())
            .map_response(|r: Response<_>| r.map(BoxBody::new))
            .layer(SetRequestHeaderLayer::overriding(
                USER_AGENT,
                MAS_USER_AGENT.clone(),
            ))
            // A trace that has the whole operation, with all the redirects, retries, rate limits
            .layer(OtelTraceLayer::outer_client(self.operation))
            .layer(ConcurrencyLimitLayer::new(10))
            .layer(FollowRedirectLayer::new())
            // A trace for each "real" http request
            .layer(OtelTraceLayer::inner_client())
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
            // Propagate the span context
            .map_request(|mut r: Request<_>| {
                // TODO: this seems to be broken
                let cx = tracing::Span::current().context();
                let mut injector = opentelemetry_http::HeaderInjector(r.headers_mut());
                opentelemetry::global::get_text_map_propagator(|propagator| {
                    propagator.inject_context(&cx, &mut injector);
                });

                r
            })
            .service(inner)
            .boxed_clone()
    }
}
