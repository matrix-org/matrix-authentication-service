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
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_jose::claims::ClaimError;
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::requests::{
    authorization_code::AuthorizationValidationData, jose::JwtVerificationData,
};
use mas_router::{Route, UrlBuilder};
use mas_storage::{
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    BoxClock, BoxRng, Clock, Repository,
};
use mas_storage_pg::PgRepository;
use oauth2_types::errors::ClientErrorCode;
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

use super::{client_credentials_for_provider, UpstreamSessionsCookie};
use crate::impl_from_error_for_route;

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

    #[error("Provider not found")]
    ProviderNotFound,

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

    #[error("Error from the provider: {error}")]
    ClientError {
        error: ClientErrorCode,
        error_description: Option<String>,
    },

    #[error("Missing session cookie")]
    MissingCookie,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_storage_pg::DatabaseError);
impl_from_error_for_route!(mas_http::ClientInitError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::JwksError);
impl_from_error_for_route!(mas_oidc_client::error::TokenAuthorizationCodeError);
impl_from_error_for_route!(super::ProviderCredentialsError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::ProviderNotFound => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
            Self::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found").into_response(),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            e => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    State(pool): State<PgPool>,
    State(url_builder): State<UrlBuilder>,
    State(encrypter): State<Encrypter>,
    State(keystore): State<Keystore>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(provider_id): Path<Ulid>,
    Query(params): Query<QueryParams>,
) -> Result<impl IntoResponse, RouteError> {
    let mut repo = PgRepository::from_pool(&pool).await?;

    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .ok_or(RouteError::ProviderNotFound)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, _post_auth_action) = sessions_cookie
        .find_session(provider_id, &params.state)
        .map_err(|_| RouteError::MissingCookie)?;

    let session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    if provider.id != session.provider_id {
        // The provider in the session cookie should match the one from the URL
        return Err(RouteError::ProviderMismatch);
    }

    if params.state != session.state_str {
        // The state in the session cookie should match the one from the params
        return Err(RouteError::StateMismatch);
    }

    if !session.is_pending() {
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
        state: session.state_str.clone(),
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
    let maybe_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &subject)
        .await?;

    let link = if let Some(link) = maybe_link {
        link
    } else {
        repo.upstream_oauth_link()
            .add(&mut rng, &clock, &provider, subject)
            .await?
    };

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(&clock, session, &link, response.id_token)
        .await?;

    let cookie_jar = sessions_cookie
        .add_link_to_session(session.id, link.id)?
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((
        cookie_jar,
        mas_router::UpstreamOAuth2Link::new(link.id).go(),
    ))
}
