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

use std::ops::RangeBounds;

use http::{header::HeaderName, Request, StatusCode};
use once_cell::sync::OnceCell;
use tower::{layer::util::Stack, Service, ServiceBuilder};
use tower_http::cors::CorsLayer;

use crate::layers::{
    body_to_bytes_response::{BodyToBytesResponse, BodyToBytesResponseLayer},
    bytes_to_body_request::{BytesToBodyRequest, BytesToBodyRequestLayer},
    catch_http_codes::{CatchHttpCodes, CatchHttpCodesLayer},
    form_urlencoded_request::{FormUrlencodedRequest, FormUrlencodedRequestLayer},
    json_request::{JsonRequest, JsonRequestLayer},
    json_response::{JsonResponse, JsonResponseLayer},
};

static PROPAGATOR_HEADERS: OnceCell<Vec<HeaderName>> = OnceCell::new();

/// Notify the CORS layer what opentelemetry propagators are being used. This
/// helps whitelisting headers in CORS requests.
///
/// # Panics
///
/// When called twice
pub fn set_propagator(propagator: &dyn opentelemetry::propagation::TextMapPropagator) {
    let headers = propagator
        .fields()
        .map(|h| HeaderName::try_from(h).unwrap())
        .collect();

    tracing::debug!(
        ?headers,
        "Headers allowed in CORS requests for trace propagators set"
    );
    PROPAGATOR_HEADERS
        .set(headers)
        .expect(concat!(module_path!(), "::set_propagator was called twice"));
}

pub trait CorsLayerExt {
    #[must_use]
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>;
}

impl CorsLayerExt for CorsLayer {
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>,
    {
        let base = PROPAGATOR_HEADERS.get().cloned().unwrap_or_default();
        let headers: Vec<_> = headers.into_iter().chain(base.into_iter()).collect();
        self.allow_headers(headers)
    }
}

pub trait ServiceExt<Body>: Sized {
    fn request_bytes_to_body(self) -> BytesToBodyRequest<Self> {
        BytesToBodyRequest::new(self)
    }

    fn response_body_to_bytes(self) -> BodyToBytesResponse<Self> {
        BodyToBytesResponse::new(self)
    }

    fn json_response<T>(self) -> JsonResponse<Self, T> {
        JsonResponse::new(self)
    }

    fn json_request<T>(self) -> JsonRequest<Self, T> {
        JsonRequest::new(self)
    }

    fn form_urlencoded_request<T>(self) -> FormUrlencodedRequest<Self, T> {
        FormUrlencodedRequest::new(self)
    }

    fn catch_http_code<M>(self, status_code: StatusCode, mapper: M) -> CatchHttpCodes<Self, M>
    where
        M: Clone,
    {
        self.catch_http_codes(status_code..=status_code, mapper)
    }

    fn catch_http_codes<B, M>(self, bounds: B, mapper: M) -> CatchHttpCodes<Self, M>
    where
        B: RangeBounds<StatusCode>,
        M: Clone,
    {
        CatchHttpCodes::new(self, bounds, mapper)
    }
}

impl<S, B> ServiceExt<B> for S where S: Service<Request<B>> {}

pub trait ServiceBuilderExt<L>: Sized {
    fn request_bytes_to_body(self) -> ServiceBuilder<Stack<BytesToBodyRequestLayer, L>>;
    fn response_body_to_bytes(self) -> ServiceBuilder<Stack<BodyToBytesResponseLayer, L>>;
    fn json_response<T>(self) -> ServiceBuilder<Stack<JsonResponseLayer<T>, L>>;
    fn json_request<T>(self) -> ServiceBuilder<Stack<JsonRequestLayer<T>, L>>;
    fn form_urlencoded_request<T>(self) -> ServiceBuilder<Stack<FormUrlencodedRequestLayer<T>, L>>;

    fn catch_http_code<M>(
        self,
        status_code: StatusCode,
        mapper: M,
    ) -> ServiceBuilder<Stack<CatchHttpCodesLayer<M>, L>>
    where
        M: Clone,
    {
        self.catch_http_codes(status_code..=status_code, mapper)
    }

    fn catch_http_codes<B, M>(
        self,
        bounds: B,
        mapper: M,
    ) -> ServiceBuilder<Stack<CatchHttpCodesLayer<M>, L>>
    where
        B: RangeBounds<StatusCode>,
        M: Clone;
}

impl<L> ServiceBuilderExt<L> for ServiceBuilder<L> {
    fn request_bytes_to_body(self) -> ServiceBuilder<Stack<BytesToBodyRequestLayer, L>> {
        self.layer(BytesToBodyRequestLayer::default())
    }

    fn response_body_to_bytes(self) -> ServiceBuilder<Stack<BodyToBytesResponseLayer, L>> {
        self.layer(BodyToBytesResponseLayer::default())
    }

    fn json_response<T>(self) -> ServiceBuilder<Stack<JsonResponseLayer<T>, L>> {
        self.layer(JsonResponseLayer::default())
    }

    fn json_request<T>(self) -> ServiceBuilder<Stack<JsonRequestLayer<T>, L>> {
        self.layer(JsonRequestLayer::default())
    }

    fn form_urlencoded_request<T>(self) -> ServiceBuilder<Stack<FormUrlencodedRequestLayer<T>, L>> {
        self.layer(FormUrlencodedRequestLayer::default())
    }

    fn catch_http_codes<B, M>(
        self,
        bounds: B,
        mapper: M,
    ) -> ServiceBuilder<Stack<CatchHttpCodesLayer<M>, L>>
    where
        B: RangeBounds<StatusCode>,
        M: Clone,
    {
        self.layer(CatchHttpCodesLayer::new(bounds, mapper))
    }
}
