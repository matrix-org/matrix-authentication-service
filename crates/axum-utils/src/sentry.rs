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

use std::convert::Infallible;

use axum::response::{IntoResponseParts, ResponseParts};
use sentry::types::Uuid;

/// A wrapper to include a Sentry event ID in the response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SentryEventID(Uuid);

impl From<Uuid> for SentryEventID {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl IntoResponseParts for SentryEventID {
    type Error = Infallible;
    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.headers_mut()
            .insert("X-Sentry-Event-ID", self.0.to_string().parse().unwrap());

        Ok(res)
    }
}
