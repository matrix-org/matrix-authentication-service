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

use axum::{response::IntoResponse, Extension, Json};
use chrono::Duration;
use hyper::StatusCode;
use mas_data_model::{TokenFormatError, TokenType};
use mas_storage::compat::{
    add_compat_access_token, add_compat_refresh_token, expire_compat_access_token,
    lookup_active_compat_refresh_token, replace_compat_refresh_token,
    CompatRefreshTokenLookupError,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationMilliSeconds};
use sqlx::PgPool;
use thiserror::Error;

use super::MatrixError;

#[derive(Debug, Deserialize)]
pub struct RequestBody {
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("invalid token")]
    InvalidToken,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) | Self::Anyhow(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::InvalidToken => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid refresh token",
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
        Self::InvalidToken
    }
}

impl From<CompatRefreshTokenLookupError> for RouteError {
    fn from(e: CompatRefreshTokenLookupError) -> Self {
        if e.not_found() {
            Self::InvalidToken
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    access_token: String,
    refresh_token: String,
    #[serde_as(as = "DurationMilliSeconds<i64>")]
    expires_in_ms: Duration,
}

pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;

    let token_type = TokenType::check(&input.refresh_token)?;

    if token_type != TokenType::CompatRefreshToken {
        return Err(RouteError::InvalidToken);
    }

    let (refresh_token, access_token, session) =
        lookup_active_compat_refresh_token(&mut txn, &input.refresh_token).await?;

    let (new_refresh_token_str, new_access_token_str) = {
        let mut rng = thread_rng();
        (
            TokenType::CompatRefreshToken.generate(&mut rng),
            TokenType::CompatAccessToken.generate(&mut rng),
        )
    };

    let expires_in = Duration::minutes(5);
    let new_access_token =
        add_compat_access_token(&mut txn, &session, new_access_token_str, Some(expires_in)).await?;
    let new_refresh_token =
        add_compat_refresh_token(&mut txn, &session, &new_access_token, new_refresh_token_str)
            .await?;

    replace_compat_refresh_token(&mut txn, &refresh_token, &new_refresh_token).await?;
    expire_compat_access_token(&mut txn, access_token).await?;

    txn.commit().await?;

    Ok(Json(ResponseBody {
        access_token: new_access_token.token,
        refresh_token: new_refresh_token.token,
        expires_in_ms: expires_in,
    }))
}
