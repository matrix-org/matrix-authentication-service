// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use axum::response::{IntoResponse, Response};
use http::StatusCode;

/// A simple wrapper around an error that implements [`IntoResponse`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ErrorWrapper<T>(#[from] pub T);

impl<T> IntoResponse for ErrorWrapper<T>
where
    T: std::error::Error,
{
    fn into_response(self) -> Response {
        // TODO: make this a bit more user friendly
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}
