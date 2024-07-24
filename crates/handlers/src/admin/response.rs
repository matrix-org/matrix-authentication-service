// Copyright 2024 The Matrix.org Foundation C.I.C.
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

#![allow(clippy::module_name_repetitions)]

use schemars::JsonSchema;
use serde::Serialize;

/// A single error
#[derive(Serialize, JsonSchema)]
struct Error {
    /// A human-readable title for the error
    title: String,
}

impl Error {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            title: error.to_string(),
        }
    }
}

/// A top-level response with a list of errors
#[derive(Serialize, JsonSchema)]
pub struct ErrorResponse {
    /// The list of errors
    errors: Vec<Error>,
}

impl ErrorResponse {
    /// Create a new error response from any Rust error
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut errors = Vec::new();
        let mut head = Some(error);
        while let Some(error) = head {
            errors.push(Error::from_error(error));
            head = error.source();
        }
        Self { errors }
    }
}
