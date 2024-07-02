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
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_templates::ErrorContext;

use crate::sentry::SentryEventID;

pub struct FancyError {
    context: ErrorContext,
}

impl FancyError {
    #[must_use]
    pub fn new(context: ErrorContext) -> Self {
        Self { context }
    }
}

impl std::fmt::Display for FancyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.context.code().unwrap_or("Internal error");
        match (self.context.description(), self.context.details()) {
            (Some(description), Some(details)) => {
                write!(f, "{code}: {description} ({details})")
            }
            (Some(message), None) | (None, Some(message)) => {
                write!(f, "{code}: {message}")
            }
            (None, None) => {
                write!(f, "{code}")
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> From<E> for FancyError {
    fn from(err: E) -> Self {
        let context = ErrorContext::new()
            .with_description(format!("{err}"))
            .with_details(format!("{err:?}"));
        FancyError { context }
    }
}

impl IntoResponse for FancyError {
    fn into_response(self) -> Response {
        let error = format!("{}", self.context);
        let event_id = sentry::capture_message(&error, sentry::Level::Error);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            TypedHeader(ContentType::text()),
            SentryEventID::from(event_id),
            Extension(self.context),
            error,
        )
            .into_response()
    }
}
