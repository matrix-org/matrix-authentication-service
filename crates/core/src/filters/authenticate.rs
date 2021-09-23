// Copyright 2021 The Matrix.org Foundation C.I.C.
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

//! Authenticate an endpoint with an access token as bearer authorization token

use chrono::Utc;
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use thiserror::Error;
use warp::{
    reject::{MissingHeader, Reject},
    reply::{with_header, with_status},
    Filter, Rejection, Reply,
};

use super::{
    database::connection,
    headers::{typed_header, InvalidTypedHeader},
};
use crate::{
    errors::wrapped_error,
    storage::oauth2::access_token::{
        lookup_access_token, AccessTokenLookupError, OAuth2AccessTokenLookup,
    },
    tokens::{self, TokenFormatError, TokenType},
};

/// Bearer token authentication failed
///
/// This is recoverable with [`recover_unauthorized`]
#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("invalid token format")]
    TokenFormat(#[from] TokenFormatError),

    #[error("invalid token type {0:?}, expected an access token")]
    WrongTokenType(TokenType),

    #[error("unknown token")]
    TokenNotFound(#[source] AccessTokenLookupError),

    #[error("token is not active")]
    TokenInactive,

    #[error("token expired")]
    TokenExpired,

    #[error("missing authorization header")]
    MissingAuthorizationHeader,

    #[error("invalid authorization header")]
    InvalidAuthorizationHeader,
}

impl Reject for AuthenticationError {}

/// Authenticate a request using an access token as a bearer authorization
///
/// # Rejections
///
/// This can reject with either a [`AuthenticationError`] or with a generic
/// wrapped sqlx error.
#[must_use]
pub fn authentication(
    pool: &PgPool,
) -> impl Filter<Extract = (OAuth2AccessTokenLookup,), Error = Rejection> + Clone + Send + Sync + 'static
{
    connection(pool)
        .and(typed_header())
        .and_then(authenticate)
        .recover(recover)
        .unify()
}

async fn authenticate(
    mut conn: PoolConnection<Postgres>,
    auth: Authorization<Bearer>,
) -> Result<OAuth2AccessTokenLookup, Rejection> {
    let token = auth.0.token();
    let token_type = tokens::check(token).map_err(AuthenticationError::TokenFormat)?;

    if token_type != tokens::TokenType::AccessToken {
        return Err(AuthenticationError::WrongTokenType(token_type).into());
    }

    let token = lookup_access_token(&mut conn, token).await.map_err(|e| {
        if e.not_found() {
            // This error happens if the token was not found and should be recovered
            warp::reject::custom(AuthenticationError::TokenNotFound(e))
        } else {
            // This is a generic database error that we want to propagate
            warp::reject::custom(wrapped_error(e))
        }
    })?;

    if !token.active {
        return Err(AuthenticationError::TokenInactive.into());
    }

    if token.exp() < Utc::now() {
        return Err(AuthenticationError::TokenExpired.into());
    }

    Ok(token)
}

/// Transform the rejections from the [`with_typed_header`] filter
async fn recover(rejection: Rejection) -> Result<OAuth2AccessTokenLookup, Rejection> {
    if rejection.find::<MissingHeader>().is_some() {
        return Err(warp::reject::custom(
            AuthenticationError::MissingAuthorizationHeader,
        ));
    }

    if rejection.find::<InvalidTypedHeader>().is_some() {
        return Err(warp::reject::custom(
            AuthenticationError::InvalidAuthorizationHeader,
        ));
    }

    Err(rejection)
}

/// Recover from an [`AuthenticationError`] with a `WWW-Authenticate` header, as
/// per [RFC6750]. This is not intended for user-facing endpoints.
///
/// [RFC6750]: https://www.rfc-editor.org/rfc/rfc6750.html
pub async fn recover_unauthorized(rejection: Rejection) -> Result<impl Reply, Rejection> {
    if rejection.find::<AuthenticationError>().is_some() {
        // TODO: have the issuer/realm here
        let reply = "invalid token";
        let reply = with_status(reply, StatusCode::UNAUTHORIZED);
        let reply = with_header(reply, "WWW-Authenticate", r#"Bearer error="invalid_token""#);
        return Ok(reply);
    }

    Err(rejection)
}
