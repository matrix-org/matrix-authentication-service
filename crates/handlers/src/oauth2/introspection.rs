// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
};
use mas_data_model::{TokenFormatError, TokenType};
use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_keystore::Encrypter;
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    user::{BrowserSessionRepository, UserRepository},
    BoxClock, BoxRepository, Clock,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{IntrospectionRequest, IntrospectionResponse},
    scope::ScopeToken,
};
use thiserror::Error;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("could not find client")]
    ClientNotFound,

    #[error("client is not allowed to introspect")]
    NotAllowed,

    #[error("unknown token")]
    UnknownToken,

    #[error("bad request")]
    BadRequest,

    #[error(transparent)]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ),
            )
                .into_response(),
            Self::ClientNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),
            Self::ClientCredentialsVerification(e) => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClient)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),
            Self::UnknownToken => Json(INACTIVE).into_response(),
            Self::NotAllowed => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::AccessDenied)),
            )
                .into_response(),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl From<TokenFormatError> for RouteError {
    fn from(_e: TokenFormatError) -> Self {
        Self::UnknownToken
    }
}

const INACTIVE: IntrospectionResponse = IntrospectionResponse {
    active: false,
    scope: None,
    client_id: None,
    username: None,
    token_type: None,
    exp: None,
    iat: None,
    nbf: None,
    sub: None,
    aud: None,
    iss: None,
    jti: None,
};

const API_SCOPE: ScopeToken = ScopeToken::from_static("urn:matrix:org.matrix.msc2967.client:api:*");

#[tracing::instrument(
    name = "handlers.oauth2.introspection.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
    err,
)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    mut repo: BoxRepository,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<IntrospectionRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await
        .unwrap()
        .ok_or(RouteError::ClientNotFound)?;

    let method = match &client.token_endpoint_auth_method {
        None | Some(OAuthClientAuthenticationMethod::None) => {
            return Err(RouteError::NotAllowed);
        }
        Some(c) => c,
    };

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    let token = &form.token;
    let token_type = TokenType::check(token)?;
    if let Some(hint) = form.token_type_hint {
        if token_type != hint {
            return Err(RouteError::UnknownToken);
        }
    }

    let reply = match token_type {
        TokenType::AccessToken => {
            let token = repo
                .oauth2_access_token()
                .find_by_token(token)
                .await?
                .filter(|t| t.is_valid(clock.now()))
                .ok_or(RouteError::UnknownToken)?;

            let session = repo
                .oauth2_session()
                .lookup(token.session_id)
                .await?
                .filter(|s| s.is_valid())
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            let browser_session = repo
                .browser_session()
                .lookup(session.user_session_id)
                .await?
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username: Some(browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: Some(token.expires_at),
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(browser_session.user.sub),
                aud: None,
                iss: None,
                jti: Some(token.jti()),
            }
        }

        TokenType::RefreshToken => {
            let token = repo
                .oauth2_refresh_token()
                .find_by_token(token)
                .await?
                .filter(|t| t.is_valid())
                .ok_or(RouteError::UnknownToken)?;

            let session = repo
                .oauth2_session()
                .lookup(token.session_id)
                .await?
                .filter(|s| s.is_valid())
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            let browser_session = repo
                .browser_session()
                .lookup(session.user_session_id)
                .await?
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username: Some(browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(browser_session.user.sub),
                aud: None,
                iss: None,
                jti: Some(token.jti()),
            }
        }

        TokenType::CompatAccessToken => {
            let access_token = repo
                .compat_access_token()
                .find_by_token(token)
                .await?
                .filter(|t| t.is_valid(clock.now()))
                .ok_or(RouteError::UnknownToken)?;

            let session = repo
                .compat_session()
                .lookup(access_token.session_id)
                .await?
                .filter(|s| s.is_valid())
                .ok_or(RouteError::UnknownToken)?;

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            let device_scope = session.device.to_scope_token();
            let scope = [API_SCOPE, device_scope].into_iter().collect();

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }

        TokenType::CompatRefreshToken => {
            let refresh_token = repo
                .compat_refresh_token()
                .find_by_token(token)
                .await?
                .filter(|t| t.is_valid())
                .ok_or(RouteError::UnknownToken)?;

            let session = repo
                .compat_session()
                .lookup(refresh_token.session_id)
                .await?
                .filter(|s| s.is_valid())
                .ok_or(RouteError::UnknownToken)?;

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                // XXX: is that the right error to bubble up?
                .ok_or(RouteError::UnknownToken)?;

            let device_scope = session.device.to_scope_token();
            let scope = [API_SCOPE, device_scope].into_iter().collect();

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
    };

    Ok(Json(reply))
}
