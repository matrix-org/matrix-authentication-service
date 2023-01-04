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

use axum::{extract::State, response::IntoResponse, Json};
use chrono::Duration;
use hyper::StatusCode;
use mas_data_model::{CompatSession, CompatSsoLoginState, Device, TokenType, User};
use mas_storage::{
    compat::{
        add_compat_access_token, add_compat_refresh_token, get_compat_sso_login_by_token,
        mark_compat_sso_login_as_exchanged, start_compat_session,
    },
    user::{UserPasswordRepository, UserRepository},
    Clock, Repository,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DurationMilliSeconds};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{MatrixError, MatrixHomeserver};
use crate::{impl_from_error_for_route, passwords::PasswordManager};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum LoginType {
    #[serde(rename = "m.login.password")]
    Password,

    // we will leave MSC3824 `actions` as undefined for this auth type as unclear
    // how it should be interpreted
    #[serde(rename = "m.login.token")]
    Token,

    #[serde(rename = "m.login.sso")]
    Sso {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        identity_providers: Vec<SsoIdentityProvider>,
        #[serde(rename = "org.matrix.msc3824.delegated_oidc_compatibility")]
        delegated_oidc_compatibility: bool,
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
                identity_providers: vec![],
                delegated_oidc_compatibility: true,
            },
            LoginType::Token,
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

    #[error("unsupported login method")]
    Unsupported,

    #[error("user not found")]
    UserNotFound,

    #[error("user has no password")]
    NoPassword,

    #[error("password verification failed")]
    PasswordVerificationFailed(#[source] anyhow::Error),

    #[error("login took too long")]
    LoginTookTooLong,

    #[error("invalid login token")]
    InvalidLoginToken,
}

impl_from_error_for_route!(sqlx::Error);
impl_from_error_for_route!(mas_storage::DatabaseError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal server error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Unsupported => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "Invalid login type",
                status: StatusCode::BAD_REQUEST,
            },
            Self::UserNotFound | Self::NoPassword | Self::PasswordVerificationFailed(_) => {
                MatrixError {
                    errcode: "M_UNAUTHORIZED",
                    error: "Invalid username/password",
                    status: StatusCode::FORBIDDEN,
                }
            }
            Self::LoginTookTooLong => MatrixError {
                errcode: "M_UNAUTHORIZED",
                error: "Login token expired",
                status: StatusCode::FORBIDDEN,
            },
            Self::InvalidLoginToken => MatrixError {
                errcode: "M_UNAUTHORIZED",
                error: "Invalid login token",
                status: StatusCode::FORBIDDEN,
            },
        }
        .into_response()
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    State(password_manager): State<PasswordManager>,
    State(pool): State<PgPool>,
    State(homeserver): State<MatrixHomeserver>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let (clock, mut rng) = crate::clock_and_rng();
    let mut txn = pool.begin().await?;
    let (session, user) = match input.credentials {
        Credentials::Password {
            identifier: Identifier::User { user },
            password,
        } => user_password_login(&password_manager, &mut txn, user, password).await?,

        Credentials::Token { token } => token_login(&mut txn, &clock, &token).await?,

        _ => {
            return Err(RouteError::Unsupported);
        }
    };

    let user_id = format!("@{username}:{homeserver}", username = user.username);

    // If the client asked for a refreshable token, make it expire
    let expires_in = if input.refresh_token {
        // TODO: this should be configurable
        Some(Duration::minutes(5))
    } else {
        None
    };

    let access_token = TokenType::CompatAccessToken.generate(&mut rng);
    let access_token = add_compat_access_token(
        &mut txn,
        &mut rng,
        &clock,
        &session,
        access_token,
        expires_in,
    )
    .await?;

    let refresh_token = if input.refresh_token {
        let refresh_token = TokenType::CompatRefreshToken.generate(&mut rng);
        let refresh_token = add_compat_refresh_token(
            &mut txn,
            &mut rng,
            &clock,
            &session,
            &access_token,
            refresh_token,
        )
        .await?;
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
    clock: &Clock,
    token: &str,
) -> Result<(CompatSession, User), RouteError> {
    let login = get_compat_sso_login_by_token(&mut *txn, token)
        .await?
        .ok_or(RouteError::InvalidLoginToken)?;

    let now = clock.now();
    let user_id = match login.state {
        CompatSsoLoginState::Pending => {
            tracing::error!(
                compat_sso_login.id = %login.id,
                "Exchanged a token for a login that was not fullfilled yet"
            );
            return Err(RouteError::InvalidLoginToken);
        }
        CompatSsoLoginState::Fulfilled {
            fulfilled_at: fullfilled_at,
            ref session,
            ..
        } => {
            if now > fullfilled_at + Duration::seconds(30) {
                return Err(RouteError::LoginTookTooLong);
            }

            session.user_id
        }
        CompatSsoLoginState::Exchanged { exchanged_at, .. } => {
            if now > exchanged_at + Duration::seconds(30) {
                // TODO: log that session out
                tracing::error!(
                    compat_sso_login.id = %login.id,
                    "Login token exchanged a second time more than 30s after"
                );
            }

            return Err(RouteError::InvalidLoginToken);
        }
    };

    let user = txn
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::UserNotFound)?;

    let login = mark_compat_sso_login_as_exchanged(&mut *txn, clock, login).await?;

    match login.state {
        CompatSsoLoginState::Exchanged { session, .. } => Ok((session, user)),
        _ => unreachable!(),
    }
}

async fn user_password_login(
    password_manager: &PasswordManager,
    txn: &mut Transaction<'_, Postgres>,
    username: String,
    password: String,
) -> Result<(CompatSession, User), RouteError> {
    let (clock, mut rng) = crate::clock_and_rng();

    // Find the user
    let user = txn
        .user()
        .find_by_username(&username)
        .await?
        .ok_or(RouteError::UserNotFound)?;

    // Lookup its password
    let user_password = txn
        .user_password()
        .active(&user)
        .await?
        .ok_or(RouteError::NoPassword)?;

    // Verify the password
    let password = Zeroizing::new(password.into_bytes());

    let new_password_hash = password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
        .map_err(RouteError::PasswordVerificationFailed)?;

    if let Some((version, hashed_password)) = new_password_hash {
        // Save the upgraded password if needed
        txn.user_password()
            .add(
                &mut rng,
                &clock,
                &user,
                version,
                hashed_password,
                Some(&user_password),
            )
            .await?;
    }

    // Now that the user credentials have been verified, start a new compat session
    let device = Device::generate(&mut rng);
    let session = start_compat_session(&mut *txn, &mut rng, &clock, &user, device).await?;

    Ok((session, user))
}
