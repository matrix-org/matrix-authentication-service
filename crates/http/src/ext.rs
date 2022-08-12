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

use http::header::HeaderName;
use once_cell::sync::OnceCell;
use tower::{layer::util::Stack, ServiceBuilder};
use tower_http::cors::CorsLayer;

use crate::layers::{
    body_to_bytes::{BodyToBytes, BodyToBytesLayer},
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

pub trait ServiceExt: Sized {
    fn response_body_to_bytes(self) -> BodyToBytes<Self> {
        BodyToBytes::new(self)
    }

    fn json_response<T>(self) -> JsonResponse<Self, T> {
        JsonResponse::new(self)
    }

    fn json_request<T>(self) -> JsonRequest<Self, T> {
        JsonRequest::new(self)
    }
}

impl<S> ServiceExt for S {}

pub trait ServiceBuilderExt<L>: Sized {
    fn response_to_bytes(self) -> ServiceBuilder<Stack<BodyToBytesLayer, L>>;
    fn json_response<T>(self) -> ServiceBuilder<Stack<JsonResponseLayer<T>, L>>;
    fn json_request<T>(self) -> ServiceBuilder<Stack<JsonRequestLayer<T>, L>>;
}

impl<L> ServiceBuilderExt<L> for ServiceBuilder<L> {
    fn response_to_bytes(self) -> ServiceBuilder<Stack<BodyToBytesLayer, L>> {
        self.layer(BodyToBytesLayer::default())
    }

    fn json_response<T>(self) -> ServiceBuilder<Stack<JsonResponseLayer<T>, L>> {
        self.layer(JsonResponseLayer::default())
    }

    fn json_request<T>(self) -> ServiceBuilder<Stack<JsonRequestLayer<T>, L>> {
        self.layer(JsonRequestLayer::default())
    }
}
