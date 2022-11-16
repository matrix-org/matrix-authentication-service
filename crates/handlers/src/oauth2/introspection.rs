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
use mas_axum_utils::client_authorization::{ClientAuthorization, CredentialsVerificationError};
use mas_data_model::{TokenFormatError, TokenType};
use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_keystore::Encrypter;
use mas_storage::{
    compat::{
        lookup_active_compat_access_token, lookup_active_compat_refresh_token,
        CompatAccessTokenLookupError, CompatRefreshTokenLookupError,
    },
    oauth2::{
        access_token::{lookup_active_access_token, AccessTokenLookupError},
        client::ClientFetchError,
        refresh_token::{lookup_active_refresh_token, RefreshTokenLookupError},
    },
    Clock, LookupError,
};
use oauth2_types::requests::{IntrospectionRequest, IntrospectionResponse};
use sqlx::PgPool;
use thiserror::Error;

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
        match self {
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Self::ClientNotFound => (StatusCode::UNAUTHORIZED, "client not found").into_response(),
            Self::UnknownToken => Json(INACTIVE).into_response(),
            Self::NotAllowed => (
                StatusCode::UNAUTHORIZED,
                "client can't use the introspection endpoint",
            )
                .into_response(),
            Self::BadRequest => StatusCode::BAD_REQUEST.into_response(),
            Self::ClientCredentialsVerification(_c) => (
                StatusCode::UNAUTHORIZED,
                "could not verify client credentials",
            )
                .into_response(),
        }
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<TokenFormatError> for RouteError {
    fn from(_e: TokenFormatError) -> Self {
        Self::UnknownToken
    }
}

impl From<ClientFetchError> for RouteError {
    fn from(e: ClientFetchError) -> Self {
        if e.not_found() {
            Self::ClientNotFound
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl From<AccessTokenLookupError> for RouteError {
    fn from(e: AccessTokenLookupError) -> Self {
        if e.not_found() {
            Self::UnknownToken
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl From<CompatAccessTokenLookupError> for RouteError {
    fn from(e: CompatAccessTokenLookupError) -> Self {
        if e.not_found() {
            Self::UnknownToken
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl From<RefreshTokenLookupError> for RouteError {
    fn from(e: RefreshTokenLookupError) -> Self {
        if e.not_found() {
            Self::UnknownToken
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl From<CompatRefreshTokenLookupError> for RouteError {
    fn from(e: CompatRefreshTokenLookupError) -> Self {
        if e.not_found() {
            Self::UnknownToken
        } else {
            Self::Internal(Box::new(e))
        }
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

#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    State(pool): State<PgPool>,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<IntrospectionRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let clock = Clock::default();
    let mut conn = pool.acquire().await?;

    let client = client_authorization.credentials.fetch(&mut conn).await?;

    let method = match &client.token_endpoint_auth_method {
        None | Some(OAuthClientAuthenticationMethod::None) => {
            return Err(RouteError::NotAllowed);
        }
        Some(c) => c,
    };

    client_authorization
        .credentials
        .verify(&encrypter, method, &client)
        .await?;

    let form = if let Some(form) = client_authorization.form {
        form
    } else {
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
            let (token, session) = lookup_active_access_token(&mut conn, token).await?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: Some(token.expires_at),
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.browser_session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
        TokenType::RefreshToken => {
            let (token, session) = lookup_active_refresh_token(&mut conn, token).await?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.browser_session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
        TokenType::CompatAccessToken => {
            let (token, session) =
                lookup_active_compat_access_token(&mut conn, &clock, token).await?;

            let device_scope = session.device.to_scope_token();
            let scope = [device_scope].into_iter().collect();

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(session.user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: token.expires_at,
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
        TokenType::CompatRefreshToken => {
            let (refresh_token, _access_token, session) =
                lookup_active_compat_refresh_token(&mut conn, token).await?;

            let device_scope = session.device.to_scope_token();
            let scope = [device_scope].into_iter().collect();

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(session.user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: Some(session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
    };

    Ok(Json(reply))
}
