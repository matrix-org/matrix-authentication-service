// Copyright 2021 The Matrix.org Foundation C.I.C.
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

//! Wrapper around [`warp::filters::cors`]

use std::string::ToString;

use once_cell::sync::OnceCell;

static PROPAGATOR_HEADERS: OnceCell<Vec<String>> = OnceCell::new();

/// Notify the CORS filter what opentelemetry propagators are being used. This
/// helps whitelisting headers in CORS requests.
pub fn set_propagator(propagator: &dyn opentelemetry::propagation::TextMapPropagator) {
    let headers = propagator.fields().map(ToString::to_string).collect();
    tracing::debug!(
        ?headers,
        "Headers allowed in CORS requests for trace propagators set"
    );
    PROPAGATOR_HEADERS
        .set(headers)
        .expect(concat!(module_path!(), "::set_propagator was called twice"));
}

/// Create a wrapping filter that exposes CORS behavior for a wrapped filter.
#[must_use]
pub fn cors() -> warp::filters::cors::Builder {
    warp::filters::cors::cors()
        .allow_any_origin()
        .allow_headers(PROPAGATOR_HEADERS.get().unwrap_or(&Vec::new()))
}
