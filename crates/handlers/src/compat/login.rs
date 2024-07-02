// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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
use axum_extra::typed_header::TypedHeader;
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::sentry::SentryEventID;
use mas_data_model::{
    CompatSession, CompatSsoLoginState, Device, SiteConfig, TokenType, User, UserAgent,
};
use mas_matrix::BoxHomeserverConnection;
use mas_storage::{
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
        CompatSsoLoginRepository,
    },
    job::{JobRepositoryExt, ProvisionDeviceJob},
    user::{UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DurationMilliSeconds};
use thiserror::Error;
use zeroize::Zeroizing;

use super::MatrixError;
use crate::{impl_from_error_for_route, passwords::PasswordManager, BoundActivityTracker};

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

#[tracing::instrument(name = "handlers.compat.login.get", skip_all)]
pub(crate) async fn get(State(password_manager): State<PasswordManager>) -> impl IntoResponse {
    let flows = if password_manager.is_enabled() {
        vec![
            LoginType::Password,
            LoginType::Sso {
                identity_providers: vec![],
                delegated_oidc_compatibility: true,
            },
            LoginType::Token,
        ]
    } else {
        vec![
            LoginType::Sso {
                identity_providers: vec![],
                delegated_oidc_compatibility: true,
            },
            LoginType::Token,
        ]
    };

    let res = LoginTypes { flows };

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
#[derive(Debug, Serialize, Deserialize)]
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

    #[error("session not found")]
    SessionNotFound,

    #[error("user has no password")]
    NoPassword,

    #[error("password verification failed")]
    PasswordVerificationFailed(#[source] anyhow::Error),

    #[error("login took too long")]
    LoginTookTooLong,

    #[error("invalid login token")]
    InvalidLoginToken,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::Internal(_) | Self::SessionNotFound => MatrixError {
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
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

#[tracing::instrument(name = "handlers.compat.login.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(password_manager): State<PasswordManager>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    State(homeserver): State<BoxHomeserverConnection>,
    State(site_config): State<SiteConfig>,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    let (mut session, user) = match (password_manager.is_enabled(), input.credentials) {
        (
            true,
            Credentials::Password {
                identifier: Identifier::User { user },
                password,
            },
        ) => {
            user_password_login(
                &mut rng,
                &clock,
                &password_manager,
                &mut repo,
                user,
                password,
            )
            .await?
        }

        (_, Credentials::Token { token }) => token_login(&mut repo, &clock, &token).await?,

        _ => {
            return Err(RouteError::Unsupported);
        }
    };

    if let Some(user_agent) = user_agent {
        session = repo
            .compat_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let user_id = homeserver.mxid(&user.username);

    // If the client asked for a refreshable token, make it expire
    let expires_in = if input.refresh_token {
        Some(site_config.compat_token_ttl)
    } else {
        None
    };

    let access_token = TokenType::CompatAccessToken.generate(&mut rng);
    let access_token = repo
        .compat_access_token()
        .add(&mut rng, &clock, &session, access_token, expires_in)
        .await?;

    let refresh_token = if input.refresh_token {
        let refresh_token = TokenType::CompatRefreshToken.generate(&mut rng);
        let refresh_token = repo
            .compat_refresh_token()
            .add(&mut rng, &clock, &session, &access_token, refresh_token)
            .await?;
        Some(refresh_token.token)
    } else {
        None
    };

    repo.save().await?;

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    Ok(Json(ResponseBody {
        access_token: access_token.token,
        device_id: session.device,
        user_id,
        refresh_token,
        expires_in_ms: expires_in,
    }))
}

async fn token_login(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    token: &str,
) -> Result<(CompatSession, User), RouteError> {
    let login = repo
        .compat_sso_login()
        .find_by_token(token)
        .await?
        .ok_or(RouteError::InvalidLoginToken)?;

    let now = clock.now();
    let session_id = match login.state {
        CompatSsoLoginState::Pending => {
            tracing::error!(
                compat_sso_login.id = %login.id,
                "Exchanged a token for a login that was not fullfilled yet"
            );
            return Err(RouteError::InvalidLoginToken);
        }
        CompatSsoLoginState::Fulfilled {
            fulfilled_at,
            session_id,
            ..
        } => {
            if now > fulfilled_at + Duration::microseconds(30 * 1000 * 1000) {
                return Err(RouteError::LoginTookTooLong);
            }

            session_id
        }
        CompatSsoLoginState::Exchanged {
            exchanged_at,
            session_id,
            ..
        } => {
            if now > exchanged_at + Duration::microseconds(30 * 1000 * 1000) {
                // TODO: log that session out
                tracing::error!(
                    compat_sso_login.id = %login.id,
                    compat_session.id = %session_id,
                    "Login token exchanged a second time more than 30s after"
                );
            }

            return Err(RouteError::InvalidLoginToken);
        }
    };

    let session = repo
        .compat_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        .filter(mas_data_model::User::is_valid)
        .ok_or(RouteError::UserNotFound)?;

    repo.compat_sso_login().exchange(clock, login).await?;

    Ok((session, user))
}

async fn user_password_login(
    mut rng: &mut (impl RngCore + CryptoRng + Send),
    clock: &impl Clock,
    password_manager: &PasswordManager,
    repo: &mut BoxRepository,
    username: String,
    password: String,
) -> Result<(CompatSession, User), RouteError> {
    // Find the user
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .filter(mas_data_model::User::is_valid)
        .ok_or(RouteError::UserNotFound)?;

    // Lookup its password
    let user_password = repo
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
        repo.user_password()
            .add(
                &mut rng,
                clock,
                &user,
                version,
                hashed_password,
                Some(&user_password),
            )
            .await?;
    }

    // Now that the user credentials have been verified, start a new compat session
    let device = Device::generate(&mut rng);
    repo.job()
        .schedule_job(ProvisionDeviceJob::new(&user, &device))
        .await?;

    let session = repo
        .compat_session()
        .add(&mut rng, clock, &user, device, None, false)
        .await?;

    Ok((session, user))
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use rand::distributions::{Alphanumeric, DistString};
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{setup, RequestBuilderExt, ResponseExt, TestState};

    /// Test that the server advertises the right login flows.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Now let's get the login flows
        let request = Request::get("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body,
            serde_json::json!({
                "flows": [
                    {
                        "type": "m.login.password",
                    },
                    {
                        "type": "m.login.sso",
                        "org.matrix.msc3824.delegated_oidc_compatibility": true,
                    },
                    {
                        "type": "m.login.token",
                    }
                ],
            })
        );
    }

    /// Test that the server doesn't allow login with a password if the password
    /// manager is disabled
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = {
            let mut state = TestState::from_pool(pool).await.unwrap();
            state.password_manager = PasswordManager::disabled();
            state
        };

        // Now let's get the login flows
        let request = Request::get("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body,
            serde_json::json!({
                "flows": [
                    {
                        "type": "m.login.sso",
                        "org.matrix.msc3824.delegated_oidc_compatibility": true,
                    },
                    {
                        "type": "m.login.token",
                    }
                ],
            })
        );

        // Try to login with a password, it should be rejected
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    }

    /// Test that a user can login with a password using the Matrix
    /// compatibility API.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_password_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Let's provision a user and add a password to it. This part is hard to test
        // with just HTTP requests, so we'll use the repository directly.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let (version, hashed_password) = state
            .password_manager
            .hash(
                &mut state.rng(),
                Zeroizing::new("password".to_owned().into_bytes()),
            )
            .await
            .unwrap();

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock,
                &user,
                version,
                hashed_password,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now let's try to login with the password, without asking for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id.as_str().len(), 10);
        assert_eq!(body.user_id, "@alice:example.com");
        assert_eq!(body.refresh_token, None);
        assert_eq!(body.expires_in_ms, None);

        // Do the same, but this time ask for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
            "refresh_token": true,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id.as_str().len(), 10);
        assert_eq!(body.user_id, "@alice:example.com");
        assert!(body.refresh_token.is_some());
        assert!(body.expires_in_ms.is_some());

        // Try to login with a wrong password.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "wrongpassword",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNAUTHORIZED");

        // Try to login with a wrong username.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "bob",
            },
            "password": "wrongpassword",
        }));

        let old_body = body;
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();

        // The response should be the same as the previous one, so that we don't leak if
        // it's the user that is invalid or the password.
        assert_eq!(body, old_body);
    }

    /// Test the response of an unsupported login flow.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unsupported_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Try to login with an unsupported login flow.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.unsupported",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    }

    /// Test `m.login.token` login flow.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_token_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a user
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // First try with an invalid token
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": "someinvalidtoken",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNAUTHORIZED");

        let (device, token) = get_login_token(&state, &user).await;

        // Try to login with the token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id, device);
        assert_eq!(body.user_id, "@alice:example.com");
        assert_eq!(body.refresh_token, None);
        assert_eq!(body.expires_in_ms, None);

        // Try again with the same token, it should fail.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNAUTHORIZED");

        // Try to login, but wait too long before sending the request.
        let (_device, token) = get_login_token(&state, &user).await;

        // Advance the clock to make the token expire.
        state
            .clock
            .advance(Duration::microseconds(60 * 1000 * 1000));

        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNAUTHORIZED");
    }

    /// Get a login token for a user.
    /// Returns the device and the token.
    ///
    /// # Panics
    ///
    /// Panics if the repository fails.
    async fn get_login_token(state: &TestState, user: &User) -> (Device, String) {
        // XXX: This is a bit manual, but this is what basically the SSO login flow
        // does.
        let mut repo = state.repository().await.unwrap();

        // Generate a device and a token randomly
        let token = Alphanumeric.sample_string(&mut state.rng(), 32);
        let device = Device::generate(&mut state.rng());

        // Start a compat SSO login flow
        let login = repo
            .compat_sso_login()
            .add(
                &mut state.rng(),
                &state.clock,
                token.clone(),
                "http://example.com/".parse().unwrap(),
            )
            .await
            .unwrap();

        // Complete the flow by fulfilling it with a session
        let compat_session = repo
            .compat_session()
            .add(
                &mut state.rng(),
                &state.clock,
                user,
                device.clone(),
                None,
                false,
            )
            .await
            .unwrap();

        repo.compat_sso_login()
            .fulfill(&state.clock, login, &compat_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        (device, token)
    }
}
