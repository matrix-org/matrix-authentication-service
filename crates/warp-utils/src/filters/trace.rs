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

//! Route tracing utility

use std::convert::Infallible;

use warp::Filter;

/// Set the name of that route
#[must_use]
pub fn name(
    name: &'static str,
) -> impl Filter<Extract = (), Error = Infallible> + Clone + Send + Sync + 'static {
    warp::any()
        .map(move || {
            // TODO: update_name has a weird signature, which is already fixed in
            // opentelemetry-rust, just not released yet
            // TODO: we should find another way to classify requests. Span::update_name has
            // impacts on sampling and should not be used
            opentelemetry::trace::get_active_span(|s| s.update_name::<String>(name.to_string()));
        })
        .untuple_one()
}
