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

use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use serde::Serialize;

pub(crate) mod login;
pub(crate) mod login_sso_complete;
pub(crate) mod login_sso_redirect;
pub(crate) mod logout;
pub(crate) mod refresh;

#[derive(Debug, Clone)]
pub struct MatrixHomeserver(String);

impl MatrixHomeserver {
    #[must_use]
    pub const fn new(hs: String) -> Self {
        Self(hs)
    }
}

impl std::fmt::Display for MatrixHomeserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Serialize)]
struct MatrixError {
    errcode: &'static str,
    error: &'static str,
    #[serde(skip)]
    status: StatusCode,
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self)).into_response()
    }
}
