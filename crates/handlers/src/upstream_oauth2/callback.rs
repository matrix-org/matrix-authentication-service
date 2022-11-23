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

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_http::ClientInitError;
use mas_jose::claims::ClaimError;
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::{
    error::{DiscoveryError, JwksError, TokenAuthorizationCodeError},
    requests::{authorization_code::AuthorizationValidationData, jose::JwtVerificationData},
};
use mas_router::UrlBuilder;
use mas_storage::{
    upstream_oauth2::{add_link, complete_session, lookup_link_by_subject, lookup_session},
    GenericLookupError, LookupResultExt,
};
use oauth2_types::errors::ClientErrorCode;
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

use super::{client_credentials_for_provider, ProviderCredentialsError};

#[derive(Deserialize)]
pub struct QueryParams {
    state: String,

    #[serde(flatten)]
    code_or_error: CodeOrError,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CodeOrError {
    Code {
        code: String,
    },
    Error {
        error: ClientErrorCode,
        error_description: Option<String>,
        #[allow(dead_code)]
        error_uri: Option<String>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Provider mismatch")]
    ProviderMismatch,

    #[error("Session already completed")]
    AlreadyCompleted,

    #[error("State parameter mismatch")]
    StateMismatch,

    #[error("Missing ID token")]
    MissingIDToken,

    #[error("Invalid ID token")]
    InvalidIdToken(#[from] ClaimError),

    #[error("User already linked")]
    UserAlreadyLinked,

    #[error("Error from the provider: {error}")]
    ClientError {
        error: ClientErrorCode,
        error_description: Option<String>,
    },

    #[error("Missing session cookie")]
    MissingCookie,

    #[error("Invalid session cookie")]
    InvalidCookie(#[source] ulid::DecodeError),

    #[error(transparent)]
    InternalError(Box<dyn std::error::Error>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<GenericLookupError> for RouteError {
    fn from(e: GenericLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<DiscoveryError> for RouteError {
    fn from(e: DiscoveryError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<JwksError> for RouteError {
    fn from(e: JwksError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<TokenAuthorizationCodeError> for RouteError {
    fn from(e: TokenAuthorizationCodeError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<mas_storage::upstream_oauth2::SessionLookupError> for RouteError {
    fn from(e: mas_storage::upstream_oauth2::SessionLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<ClientInitError> for RouteError {
    fn from(e: ClientInitError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<ProviderCredentialsError> for RouteError {
    fn from(e: ProviderCredentialsError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found").into_response(),
            Self::InternalError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            Self::Anyhow(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response()
            }
            e => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn get(
    State(http_client_factory): State<HttpClientFactory>,
    State(pool): State<PgPool>,
    State(url_builder): State<UrlBuilder>,
    State(encrypter): State<Encrypter>,
    State(keystore): State<Keystore>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(provider_id): Path<Ulid>,
    Query(params): Query<QueryParams>,
) -> Result<impl IntoResponse, RouteError> {
    let (clock, mut rng) = crate::rng_and_clock()?;

    let mut txn = pool.begin().await?;

    // XXX: that cookie should be managed elsewhere
    let cookie = cookie_jar
        .get("upstream-oauth2-session-id")
        .ok_or(RouteError::MissingCookie)?;

    let session_id: Ulid = cookie.value().parse().map_err(RouteError::InvalidCookie)?;

    let (provider, session) = lookup_session(&mut txn, session_id)
        .await
        .to_option()?
        .ok_or(RouteError::SessionNotFound)?;

    if provider.id != provider_id {
        // The provider in the session cookie should match the one from the URL
        return Err(RouteError::ProviderMismatch);
    }

    if params.state != session.state {
        // The state in the session cookie should match the one from the params
        return Err(RouteError::StateMismatch);
    }

    if session.completed() {
        // The session was already completed
        return Err(RouteError::AlreadyCompleted);
    }

    // Let's extract the code from the params, and return if there was an error
    let code = match params.code_or_error {
        CodeOrError::Error {
            error,
            error_description,
            ..
        } => {
            return Err(RouteError::ClientError {
                error,
                error_description,
            })
        }
        CodeOrError::Code { code } => code,
    };

    let http_service = http_client_factory
        .http_service("upstream-discover")
        .await?;

    // XXX: we shouldn't discover on-the-fly
    // Discover the provider
    let metadata =
        mas_oidc_client::requests::discovery::discover(&http_service, &provider.issuer).await?;

    let http_service = http_client_factory
        .http_service("upstream-fetch-jwks")
        .await?;

    // Fetch the JWKS
    let jwks =
        mas_oidc_client::requests::jose::fetch_jwks(&http_service, metadata.jwks_uri()).await?;

    // Figure out the client credentials
    let client_credentials = client_credentials_for_provider(
        &provider,
        metadata.token_endpoint(),
        &keystore,
        &encrypter,
    )?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    // TODO: all that should be borrowed
    let validation_data = AuthorizationValidationData {
        state: session.state.clone(),
        nonce: session.nonce.clone(),
        code_challenge_verifier: session.code_challenge_verifier.clone(),
        redirect_uri,
    };

    let id_token_verification_data = JwtVerificationData {
        issuer: &provider.issuer,
        jwks: &jwks,
        // TODO: make that configurable
        signing_algorithm: &mas_iana::jose::JsonWebSignatureAlg::Rs256,
        client_id: &provider.client_id,
    };

    let http_service = http_client_factory
        .http_service("upstream-exchange-code")
        .await?;

    let (response, id_token) =
        mas_oidc_client::requests::authorization_code::access_token_with_authorization_code(
            &http_service,
            client_credentials,
            metadata.token_endpoint(),
            code,
            validation_data,
            Some(id_token_verification_data),
            clock.now(),
            &mut rng,
        )
        .await?;

    let (_header, mut id_token) = id_token.ok_or(RouteError::MissingIDToken)?.into_parts();

    // Extract the subject from the id_token
    let subject = mas_jose::claims::SUB.extract_required(&mut id_token)?;

    // Look for an existing link
    let maybe_link = lookup_link_by_subject(&mut txn, &provider, &subject)
        .await
        .to_option()?;

    let link = if let Some((link, maybe_user_id)) = maybe_link {
        if let Some(_user_id) = maybe_user_id {
            // TODO: Here we should login if the user is linked
            return Err(RouteError::UserAlreadyLinked);
        }

        link
    } else {
        add_link(&mut txn, &mut rng, &clock, &provider, subject).await?
    };

    let _session = complete_session(&mut txn, &clock, session, &link).await?;

    txn.commit().await?;

    Ok(Json(response))
}
