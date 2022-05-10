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

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension,
};
use mas_templates::ErrorContext;

pub struct FancyError {
    context: ErrorContext,
}

impl<E: std::fmt::Display> From<E> for FancyError {
    fn from(err: E) -> Self {
        let context = ErrorContext::new().with_description(err.to_string());
        FancyError { context }
    }
}

impl IntoResponse for FancyError {
    fn into_response(self) -> Response {
        let error = format!("{:?}", self.context);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Extension(self.context),
            error,
        )
            .into_response()
    }
}
