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

use std::collections::HashMap;

use axum::{extract::State, response::IntoResponse, Json};
use chrono::{DateTime, Duration, Utc};
use headers::{CacheControl, HeaderMap, HeaderMapExt, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
};
use mas_data_model::{AuthorizationGrantStage, Client, TokenType};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, hash_token},
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::{Encrypter, Keystore};
use mas_router::UrlBuilder;
use mas_storage::{
    oauth2::{
        access_token::{add_access_token, revoke_access_token},
        authorization_grant::{exchange_grant, lookup_grant_by_code},
        end_oauth_session,
        refresh_token::{add_refresh_token, consume_refresh_token, lookup_active_refresh_token},
    },
    user::BrowserSessionRepository,
    Repository,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce::CodeChallengeError,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, RefreshTokenGrant,
    },
    scope,
};
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::impl_from_error_for_route;

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug)]
struct CustomClaims {
    #[serde(rename = "iss")]
    issuer: Url,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "aud")]
    audiences: Vec<String>,
    nonce: Option<String>,
    #[serde_as(as = "Option<serde_with::TimestampSeconds>")]
    auth_time: Option<DateTime<Utc>>,
    at_hash: String,
    c_hash: String,
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("could not verify client credentials")]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("grant not found")]
    GrantNotFound,

    #[error("invalid grant")]
    InvalidGrant,

    #[error("unauthorized client")]
    UnauthorizedClient,

    #[error("no suitable key found for signing")]
    InvalidSigningKey,

    #[error("failed to load browser session")]
    NoSuchBrowserSession,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) | Self::InvalidSigningKey | Self::NoSuchBrowserSession => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            ),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            ),
            Self::PkceVerification(err) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description(format!("PKCE verification failed: {err}")),
                ),
            ),
            Self::ClientNotFound | Self::ClientCredentialsVerification(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            ),
            Self::ClientNotAllowed | Self::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),
            Self::InvalidGrant | Self::GrantNotFound => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidGrant)),
            ),
        }
        .into_response()
    }
}

impl_from_error_for_route!(sqlx::Error);
impl_from_error_for_route!(mas_storage::DatabaseError);
impl_from_error_for_route!(mas_keystore::WrongAlgorithmError);
impl_from_error_for_route!(mas_jose::claims::ClaimError);
impl_from_error_for_route!(mas_jose::claims::TokenHashError);
impl_from_error_for_route!(mas_jose::jwt::JwtSignatureError);

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    State(http_client_factory): State<HttpClientFactory>,
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    State(pool): State<PgPool>,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<AccessTokenRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;

    let client = client_authorization
        .credentials
        .fetch(&mut txn)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    let form = client_authorization.form.ok_or(RouteError::BadRequest)?;

    let reply = match form {
        AccessTokenRequest::AuthorizationCode(grant) => {
            authorization_code_grant(&grant, &client, &key_store, &url_builder, txn).await?
        }
        AccessTokenRequest::RefreshToken(grant) => {
            refresh_token_grant(&grant, &client, txn).await?
        }
        _ => {
            return Err(RouteError::InvalidGrant);
        }
    };

    let mut headers = HeaderMap::new();
    headers.typed_insert(CacheControl::new().with_no_store());
    headers.typed_insert(Pragma::no_cache());

    Ok((headers, Json(reply)))
}

#[allow(clippy::too_many_lines)]
async fn authorization_code_grant(
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    mut txn: Transaction<'_, Postgres>,
) -> Result<AccessTokenResponse, RouteError> {
    let (clock, mut rng) = crate::clock_and_rng();

    // TODO: there is a bunch of unnecessary cloning here
    // TODO: handle "not found" cases
    let authz_grant = lookup_grant_by_code(&mut txn, &grant.code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let now = clock.now();

    let session = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session,
        } => {
            debug!(%exchanged_at, %fulfilled_at, "Authorization code was already exchanged");

            // Ending the session if the token was already exchanged more than 20s ago
            if now - exchanged_at > Duration::seconds(20) {
                debug!("Ending potentially compromised session");
                end_oauth_session(&mut txn, &clock, session).await?;
                txn.commit().await?;
            }

            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Pending => {
            debug!("Authorization grant has not been fulfilled yet");
            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Fulfilled {
            ref session,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::minutes(10) {
                debug!("Code exchange took more than 10 minutes");
                return Err(RouteError::InvalidGrant);
            }

            session
        }
    };

    // This should never happen, since we looked up in the database using the code
    let code = authz_grant.code.as_ref().ok_or(RouteError::InvalidGrant)?;

    if client.id != session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return Err(RouteError::BadRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            pkce.verify(verifier)?;
        }
    };

    let browser_session = txn
        .browser_session()
        .lookup(session.user_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession)?;

    let ttl = Duration::minutes(5);
    let access_token_str = TokenType::AccessToken.generate(&mut rng);
    let refresh_token_str = TokenType::RefreshToken.generate(&mut rng);

    let access_token = add_access_token(
        &mut txn,
        &mut rng,
        &clock,
        session,
        access_token_str.clone(),
        ttl,
    )
    .await?;

    let _refresh_token = add_refresh_token(
        &mut txn,
        &mut rng,
        &clock,
        session,
        access_token,
        refresh_token_str.clone(),
    )
    .await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        let mut claims = HashMap::new();
        let now = clock.now();
        claims::ISS.insert(&mut claims, url_builder.oidc_issuer().to_string())?;
        claims::SUB.insert(&mut claims, &browser_session.user.sub)?;
        claims::AUD.insert(&mut claims, client.client_id.clone())?;
        claims::IAT.insert(&mut claims, now)?;
        claims::EXP.insert(&mut claims, now + Duration::hours(1))?;

        if let Some(ref nonce) = authz_grant.nonce {
            claims::NONCE.insert(&mut claims, nonce.clone())?;
        }
        if let Some(ref last_authentication) = browser_session.last_authentication {
            claims::AUTH_TIME.insert(&mut claims, last_authentication.created_at)?;
        }

        let alg = client
            .id_token_signed_response_alg
            .clone()
            .unwrap_or(JsonWebSignatureAlg::Rs256);
        let key = key_store
            .signing_key_for_algorithm(&alg)
            .ok_or(RouteError::InvalidSigningKey)?;

        claims::AT_HASH.insert(&mut claims, hash_token(&alg, &access_token_str)?)?;
        claims::C_HASH.insert(&mut claims, hash_token(&alg, &grant.code)?)?;

        let signer = key.params().signing_key_for_alg(&alg)?;
        let header = JsonWebSignatureHeader::new(alg)
            .with_kid(key.kid().ok_or(RouteError::InvalidSigningKey)?);
        let id_token = Jwt::sign_with_rng(&mut rng, header, claims, &signer)?;

        Some(id_token.as_str().to_owned())
    } else {
        None
    };

    let mut params = AccessTokenResponse::new(access_token_str)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token_str)
        .with_scope(session.scope.clone());

    if let Some(id_token) = id_token {
        params = params.with_id_token(id_token);
    }

    exchange_grant(&mut txn, &clock, authz_grant).await?;

    txn.commit().await?;

    Ok(params)
}

async fn refresh_token_grant(
    grant: &RefreshTokenGrant,
    client: &Client,
    mut txn: Transaction<'_, Postgres>,
) -> Result<AccessTokenResponse, RouteError> {
    let (clock, mut rng) = crate::clock_and_rng();

    let (refresh_token, session) = lookup_active_refresh_token(&mut txn, &grant.refresh_token)
        .await?
        .ok_or(RouteError::InvalidGrant)?;

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RouteError::InvalidGrant);
    }

    let ttl = Duration::minutes(5);
    let access_token_str = TokenType::AccessToken.generate(&mut rng);
    let refresh_token_str = TokenType::RefreshToken.generate(&mut rng);

    let new_access_token = add_access_token(
        &mut txn,
        &mut rng,
        &clock,
        &session,
        access_token_str.clone(),
        ttl,
    )
    .await?;

    let new_refresh_token = add_refresh_token(
        &mut txn,
        &mut rng,
        &clock,
        &session,
        new_access_token,
        refresh_token_str,
    )
    .await?;

    consume_refresh_token(&mut txn, &clock, &refresh_token).await?;

    if let Some(access_token) = refresh_token.access_token {
        revoke_access_token(&mut txn, &clock, access_token).await?;
    }

    let params = AccessTokenResponse::new(access_token_str)
        .with_expires_in(ttl)
        .with_refresh_token(new_refresh_token.refresh_token)
        .with_scope(session.scope);

    txn.commit().await?;

    Ok(params)
}
