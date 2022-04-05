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

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use axum::{extract::Extension, response::IntoResponse, Json};
use chrono::{DateTime, Duration, Utc};
use data_encoding::BASE64URL_NOPAD;
use headers::{CacheControl, HeaderMap, HeaderMapExt, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    UrlBuilder,
};
use mas_config::Encrypter;
use mas_data_model::{AuthorizationGrantStage, Client, TokenType};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, ClaimError},
    DecodedJsonWebToken, SigningKeystore, StaticKeystore,
};
use mas_storage::{
    oauth2::{
        access_token::{add_access_token, revoke_access_token},
        authorization_grant::{exchange_grant, lookup_grant_by_code},
        client::ClientFetchError,
        end_oauth_session,
        refresh_token::{
            add_refresh_token, lookup_active_refresh_token, replace_refresh_token,
            RefreshTokenLookupError,
        },
    },
    DatabaseInconsistencyError, PostgresqlBackend,
};
use oauth2_types::{
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, RefreshTokenGrant,
    },
    scope,
};
use rand::thread_rng;
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tracing::debug;
use url::Url;

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

pub(crate) enum RouteError {
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
    Anyhow(anyhow::Error),
    BadRequest,
    ClientNotFound,
    ClientNotAllowed,
    ClientCredentialsVerification(CredentialsVerificationError),
    InvalidGrant,
    UnauthorizedClient,
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

impl From<RefreshTokenLookupError> for RouteError {
    fn from(e: RefreshTokenLookupError) -> Self {
        if e.not_found() {
            Self::InvalidGrant
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        // TODO
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<ClaimError> for RouteError {
    fn from(e: ClaimError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<anyhow::Error> for RouteError {
    fn from(e: anyhow::Error) -> Self {
        Self::Anyhow(e)
    }
}

impl From<CredentialsVerificationError> for RouteError {
    fn from(e: CredentialsVerificationError) -> Self {
        Self::ClientCredentialsVerification(e)
    }
}

pub(crate) async fn post(
    client_authorization: ClientAuthorization<AccessTokenRequest>,
    Extension(key_store): Extension<Arc<StaticKeystore>>,
    Extension(url_builder): Extension<UrlBuilder>,
    Extension(pool): Extension<PgPool>,
    Extension(encrypter): Extension<Encrypter>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;

    let client = client_authorization.credentials.fetch(&mut txn).await?;

    let method = client
        .token_endpoint_auth_method
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(&encrypter, method, &client)
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

    Ok((StatusCode::OK, headers, Json(reply)))
}

fn hash<H: Digest>(mut hasher: H, token: &str) -> anyhow::Result<String> {
    hasher.update(token);
    let hash = hasher.finalize();
    // Left-most 128bit
    let bits = hash
        .get(..16)
        .context("failed to get first 128 bits of hash")?;
    Ok(BASE64URL_NOPAD.encode(bits))
}

#[allow(clippy::too_many_lines)]
async fn authorization_code_grant(
    grant: &AuthorizationCodeGrant,
    client: &Client<PostgresqlBackend>,
    key_store: &StaticKeystore,
    url_builder: &UrlBuilder,
    mut txn: Transaction<'_, Postgres>,
) -> Result<AccessTokenResponse, RouteError> {
    // TODO: there is a bunch of unnecessary cloning here
    // TODO: handle "not found" cases
    let authz_grant = lookup_grant_by_code(&mut txn, &grant.code).await?;

    // TODO: that's not a timestamp from the DB. Let's assume they are in sync
    let now = Utc::now();

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
                end_oauth_session(&mut txn, session).await?;
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
    let code = authz_grant
        .code
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!(DatabaseInconsistencyError))?;

    if client.client_id != session.client.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return Err(RouteError::BadRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            if !pkce.verify(verifier) {
                return Err(RouteError::BadRequest);
            }
        }
    };

    let browser_session = &session.browser_session;

    let ttl = Duration::minutes(5);
    let (access_token_str, refresh_token_str) = {
        let mut rng = thread_rng();
        (
            TokenType::AccessToken.generate(&mut rng),
            TokenType::RefreshToken.generate(&mut rng),
        )
    };

    let access_token = add_access_token(&mut txn, session, &access_token_str, ttl).await?;

    let _refresh_token =
        add_refresh_token(&mut txn, session, access_token, &refresh_token_str).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        let mut claims = HashMap::new();
        let now = Utc::now();
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

        claims::AT_HASH.insert(&mut claims, hash(Sha256::new(), &access_token_str)?)?;
        claims::C_HASH.insert(&mut claims, hash(Sha256::new(), &grant.code)?)?;

        let header = key_store.prepare_header(JsonWebSignatureAlg::Rs256).await?;
        let id_token = DecodedJsonWebToken::new(header, claims);
        let id_token = id_token.sign(key_store).await?;

        Some(id_token.serialize())
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

    exchange_grant(&mut txn, authz_grant).await?;

    txn.commit().await?;

    Ok(params)
}

async fn refresh_token_grant(
    grant: &RefreshTokenGrant,
    client: &Client<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
) -> Result<AccessTokenResponse, RouteError> {
    let (refresh_token, session) =
        lookup_active_refresh_token(&mut txn, &grant.refresh_token).await?;

    if client.client_id != session.client.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RouteError::InvalidGrant);
    }

    let ttl = Duration::minutes(5);
    let (access_token_str, refresh_token_str) = {
        let mut rng = thread_rng();
        (
            TokenType::AccessToken.generate(&mut rng),
            TokenType::RefreshToken.generate(&mut rng),
        )
    };

    let new_access_token = add_access_token(&mut txn, &session, &access_token_str, ttl).await?;

    let new_refresh_token =
        add_refresh_token(&mut txn, &session, new_access_token, &refresh_token_str).await?;

    replace_refresh_token(&mut txn, &refresh_token, &new_refresh_token).await?;

    if let Some(access_token) = refresh_token.access_token {
        revoke_access_token(&mut txn, &access_token).await?;
    }

    let params = AccessTokenResponse::new(access_token_str)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token_str)
        .with_scope(session.scope);

    txn.commit().await?;

    Ok(params)
}
