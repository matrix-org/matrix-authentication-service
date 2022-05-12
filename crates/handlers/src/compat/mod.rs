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
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum LoginType {
    #[serde(rename = "m.login.password")]
    Password,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginTypes {
    flows: Vec<LoginType>,
}

pub(crate) async fn get() -> impl IntoResponse {
    let res = LoginTypes {
        flows: vec![LoginType::Password],
    };

    Json(res)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IncomingLogin {
    #[serde(rename = "m.login.password")]
    Password {
        identifier: LoginIdentifier,
        password: String,
    },

    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LoginIdentifier {
    #[serde(rename = "m.id.user")]
    User { user: String },

    #[serde(other)]
    Unsupported,
}

pub(crate) async fn post(Json(input): Json<IncomingLogin>) -> impl IntoResponse {
    tracing::info!(?input, "Got Matrix login");
    MatrixError {
        errcode: "M_UNKNOWN",
        error: "Not implemented",
        status: StatusCode::NOT_IMPLEMENTED,
    }
}
