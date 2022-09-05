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

use axum::{extract::State, response::IntoResponse, Json, TypedHeader};
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use mas_data_model::{TokenFormatError, TokenType};
use mas_storage::compat::compat_logout;
use sqlx::PgPool;

use super::MatrixError;

pub enum RouteError {
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
    MissingAuthorization,
    InvalidAuthorization,
    LogoutFailed,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidAuthorization | Self::LogoutFailed => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
                status: StatusCode::UNAUTHORIZED,
            },
        }
        .into_response()
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<TokenFormatError> for RouteError {
    fn from(_e: TokenFormatError) -> Self {
        Self::InvalidAuthorization
    }
}

pub(crate) async fn post(
    State(pool): State<PgPool>,
    maybe_authorization: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<impl IntoResponse, RouteError> {
    let mut conn = pool.acquire().await?;

    let TypedHeader(authorization) = maybe_authorization.ok_or(RouteError::MissingAuthorization)?;

    let token = authorization.token();
    let token_type = TokenType::check(token)?;

    if token_type != TokenType::CompatAccessToken {
        return Err(RouteError::InvalidAuthorization);
    }

    compat_logout(&mut conn, token)
        .await
        .map_err(|_| RouteError::LogoutFailed)?;

    Ok(Json(serde_json::json!({})))
}
