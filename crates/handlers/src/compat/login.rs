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
use mas_config::MatrixConfig;
use mas_data_model::{CompatSession, Device, TokenType};
use mas_storage::{
    compat::{
        add_compat_access_token, add_compat_refresh_token, compat_login,
        get_compat_sso_login_by_token, mark_compat_sso_login_as_exchanged,
    },
    PostgresqlBackend,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DurationMilliSeconds};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;

use super::MatrixError;

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum LoginType {
    #[serde(rename = "m.login.password")]
    Password,

    #[serde(rename = "m.login.sso")]
    Sso {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        identity_providers: Vec<SsoIdentityProvider>,
    },
}

#[derive(Debug, Serialize)]
struct SsoIdentityProvider {
    id: &'static str,
    name: &'static str,
}

#[derive(Debug, Serialize)]
struct LoginTypes {
    flows: Vec<LoginType>,
}

pub(crate) async fn get() -> impl IntoResponse {
    let res = LoginTypes {
        flows: vec![
            LoginType::Password,
            LoginType::Sso {
                identity_providers: vec![SsoIdentityProvider {
                    id: "legacy",
                    name: "SSO",
                }],
            },
        ],
    };

    Json(res)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestBody {
    #[serde(flatten)]
    credentials: Credentials,

    #[serde(default)]
    refresh_token: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credentials {
    #[serde(rename = "m.login.password")]
    Password {
        identifier: Identifier,
        password: String,
    },

    #[serde(rename = "m.login.token")]
    Token { token: String },

    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Identifier {
    #[serde(rename = "m.id.user")]
    User { user: String },

    #[serde(other)]
    Unsupported,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    access_token: String,
    device_id: Device,
    user_id: String,
    refresh_token: Option<String>,
    #[serde_as(as = "Option<DurationMilliSeconds<i64>>")]
    expires_in_ms: Option<Duration>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("unsupported login method")]
    Unsupported,

    #[error("login failed")]
    LoginFailed,
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) | Self::Anyhow(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal server error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Unsupported => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "Invalid login type",
                status: StatusCode::BAD_REQUEST,
            },
            Self::LoginFailed => MatrixError {
                errcode: "M_UNAUTHORIZED",
                error: "Invalid username/password",
                status: StatusCode::FORBIDDEN,
            },
        }
        .into_response()
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Extension(config): Extension<MatrixConfig>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;
    let session = match input.credentials {
        Credentials::Password {
            identifier: Identifier::User { user },
            password,
        } => user_password_login(&mut txn, user, password).await?,

        Credentials::Token { token } => token_login(&mut txn, &token).await?,

        _ => {
            return Err(RouteError::Unsupported);
        }
    };

    let user_id = format!("@{}:{}", session.user.username, config.homeserver);

    // If the client asked for a refreshable token, make it expire
    let expires_in = if input.refresh_token {
        // TODO: this should be configurable
        Some(Duration::minutes(5))
    } else {
        None
    };

    let access_token = TokenType::CompatAccessToken.generate(&mut thread_rng());
    let access_token =
        add_compat_access_token(&mut txn, &session, access_token, expires_in).await?;

    let refresh_token = if input.refresh_token {
        let refresh_token = TokenType::CompatRefreshToken.generate(&mut thread_rng());
        let refresh_token =
            add_compat_refresh_token(&mut txn, &session, &access_token, refresh_token).await?;
        Some(refresh_token.token)
    } else {
        None
    };

    txn.commit().await?;

    Ok(Json(ResponseBody {
        access_token: access_token.token,
        device_id: session.device,
        user_id,
        refresh_token,
        expires_in_ms: expires_in,
    }))
}

async fn token_login(
    txn: &mut Transaction<'_, Postgres>,
    token: &str,
) -> Result<CompatSession<PostgresqlBackend>, RouteError> {
    let login = get_compat_sso_login_by_token(&mut *txn, token).await?;
    let login = mark_compat_sso_login_as_exchanged(&mut *txn, login).await?;

    match login.state {
        mas_data_model::CompatSsoLoginState::Exchanged { session, .. } => Ok(session),
        _ => unreachable!(),
    }
}

async fn user_password_login(
    txn: &mut Transaction<'_, Postgres>,
    username: String,
    password: String,
) -> Result<CompatSession<PostgresqlBackend>, RouteError> {
    let device = Device::generate(&mut thread_rng());
    let session = compat_login(txn, &username, &password, device)
        .await
        .map_err(|_| RouteError::LoginFailed)?;

    Ok(session)
}
