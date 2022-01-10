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

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use data_encoding::BASE64URL_NOPAD;
use headers::{CacheControl, Pragma};
use hyper::StatusCode;
use mas_config::{OAuth2ClientConfig, OAuth2Config};
use mas_data_model::{AuthorizationGrantStage, TokenType};
use mas_jose::{
    claims::{AT_HASH, AUD, AUTH_TIME, C_HASH, EXP, IAT, ISS, NONCE, SUB},
    DecodedJsonWebToken, JsonWebSignatureAlgorithm, SigningKeystore, StaticKeystore,
};
use mas_storage::{
    oauth2::{
        access_token::{add_access_token, revoke_access_token},
        authorization_grant::{exchange_grant, lookup_grant_by_code},
        refresh_token::{add_refresh_token, lookup_active_refresh_token, replace_refresh_token},
    },
    DatabaseInconsistencyError,
};
use mas_warp_utils::{
    errors::WrapError,
    filters::{client::client_authentication, database::connection},
    reply::with_typed_header,
};
use oauth2_types::{
    errors::{InvalidGrant, InvalidRequest, OAuth2Error, OAuth2ErrorCode, UnauthorizedClient},
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant,
        ClientAuthenticationMethod, RefreshTokenGrant,
    },
    scope::OPENID,
};
use rand::thread_rng;
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none};
use sha2::{Digest, Sha256};
use sqlx::{pool::PoolConnection, Acquire, PgPool, Postgres};
use tracing::debug;
use url::Url;
use warp::{
    filters::BoxedFilter,
    reject::Reject,
    reply::{json, with_status},
    Filter, Rejection, Reply,
};

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

#[derive(Debug)]
struct Error {
    json: serde_json::Value,
    status: StatusCode,
}

impl Reject for Error {}

fn error<T, E>(e: E) -> Result<T, Rejection>
where
    E: OAuth2ErrorCode + 'static,
{
    let status = e.status();
    let json = serde_json::to_value(e.into_response()).wrap_error()?;
    Err(Error { json, status }.into())
}

pub fn filter(
    pool: &PgPool,
    key_store: &Arc<StaticKeystore>,
    oauth2_config: &OAuth2Config,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let key_store = key_store.clone();
    let audience = oauth2_config
        .issuer
        .join("/oauth2/token")
        .unwrap()
        .to_string();
    let issuer = oauth2_config.issuer.clone();

    warp::path!("oauth2" / "token")
        .and(
            warp::post()
                .and(client_authentication(oauth2_config, audience))
                .and(warp::any().map(move || key_store.clone()))
                .and(warp::any().map(move || issuer.clone()))
                .and(connection(pool))
                .and_then(token)
                .recover(recover)
                .unify(),
        )
        .boxed()
}

async fn recover(rejection: Rejection) -> Result<Box<dyn Reply>, Rejection> {
    if let Some(Error { json, status }) = rejection.find::<Error>() {
        Ok(Box::new(with_status(warp::reply::json(json), *status)))
    } else {
        Err(rejection)
    }
}

async fn token(
    _auth: ClientAuthenticationMethod,
    client: OAuth2ClientConfig,
    req: AccessTokenRequest,
    key_store: Arc<StaticKeystore>,
    issuer: Url,
    mut conn: PoolConnection<Postgres>,
) -> Result<Box<dyn Reply>, Rejection> {
    let reply = match req {
        AccessTokenRequest::AuthorizationCode(grant) => {
            let reply =
                authorization_code_grant(&grant, &client, &key_store, issuer, &mut conn).await?;
            json(&reply)
        }
        AccessTokenRequest::RefreshToken(grant) => {
            let reply = refresh_token_grant(&grant, &client, &mut conn).await?;
            json(&reply)
        }
        _ => {
            let reply = InvalidGrant.into_response();
            json(&reply)
        }
    };

    let reply = with_typed_header(CacheControl::new().with_no_store(), reply);
    let reply = with_typed_header(Pragma::no_cache(), reply);
    Ok(Box::new(reply))
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
    client: &OAuth2ClientConfig,
    key_store: &StaticKeystore,
    issuer: Url,
    conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    // TODO: there is a bunch of unnecessary cloning here
    let mut txn = conn.begin().await.wrap_error()?;

    // TODO: handle "not found" cases
    let authz_grant = lookup_grant_by_code(&mut txn, &grant.code)
        .await
        .wrap_error()?;

    let session = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return error(InvalidGrant);
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session: _,
        } => {
            // TODO: we should invalidate the existing session if a code is used twice after
            // some period of time. See the `oidcc-codereuse-30seconds` test from the
            // conformance suite
            debug!(%exchanged_at, %fulfilled_at, "Authorization code was already exchanged");
            return error(InvalidGrant);
        }
        AuthorizationGrantStage::Pending => {
            debug!("Authorization grant has not been fulfilled yet");
            return error(InvalidGrant);
        }
        AuthorizationGrantStage::Fulfilled {
            ref session,
            fulfilled_at: _,
        } => {
            // TODO: we should check that the session was not fullfilled too long ago
            // (30s to 1min?). The main problem is getting a timestamp from the database
            session
        }
    };

    // This should never happen, since we looked up in the database using the code
    let code = authz_grant
        .code
        .as_ref()
        .ok_or(DatabaseInconsistencyError)
        .wrap_error()?;

    if client.client_id != session.client.client_id {
        return error(UnauthorizedClient);
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return error(InvalidRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            if !pkce.verify(verifier) {
                return error(InvalidRequest);
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

    let access_token = add_access_token(&mut txn, session, &access_token_str, ttl)
        .await
        .wrap_error()?;

    let _refresh_token = add_refresh_token(&mut txn, session, access_token, &refresh_token_str)
        .await
        .wrap_error()?;

    let id_token = if session.scope.contains(&OPENID) {
        let mut claims = HashMap::new();
        let now = Utc::now();
        ISS.insert(&mut claims, issuer.to_string()).wrap_error()?;
        SUB.insert(&mut claims, &browser_session.user.sub)
            .wrap_error()?;
        AUD.insert(&mut claims, client.client_id.clone())
            .wrap_error()?;
        IAT.insert(&mut claims, now).wrap_error()?;
        EXP.insert(&mut claims, now + Duration::hours(1))
            .wrap_error()?;

        if let Some(ref nonce) = authz_grant.nonce {
            NONCE.insert(&mut claims, nonce.clone()).wrap_error()?;
        }
        if let Some(ref last_authentication) = browser_session.last_authentication {
            AUTH_TIME
                .insert(&mut claims, last_authentication.created_at)
                .wrap_error()?;
        }

        AT_HASH
            .insert(
                &mut claims,
                hash(Sha256::new(), &access_token_str).wrap_error()?,
            )
            .wrap_error()?;
        C_HASH
            .insert(&mut claims, hash(Sha256::new(), &grant.code).wrap_error()?)
            .wrap_error()?;

        let header = key_store
            .prepare_header(JsonWebSignatureAlgorithm::Rs256)
            .await
            .wrap_error()?;
        let id_token = DecodedJsonWebToken::new(header, claims);
        let id_token = id_token.sign(key_store).await.wrap_error()?;

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

    exchange_grant(&mut txn, authz_grant).await.wrap_error()?;

    txn.commit().await.wrap_error()?;

    Ok(params)
}

async fn refresh_token_grant(
    grant: &RefreshTokenGrant,
    client: &OAuth2ClientConfig,
    conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    let mut txn = conn.begin().await.wrap_error()?;
    let (refresh_token, session) = lookup_active_refresh_token(&mut txn, &grant.refresh_token)
        .await
        .wrap_error()?;

    if client.client_id != session.client.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return error(InvalidGrant);
    }

    let ttl = Duration::minutes(5);
    let (access_token_str, refresh_token_str) = {
        let mut rng = thread_rng();
        (
            TokenType::AccessToken.generate(&mut rng),
            TokenType::RefreshToken.generate(&mut rng),
        )
    };

    let new_access_token = add_access_token(&mut txn, &session, &access_token_str, ttl)
        .await
        .wrap_error()?;

    let new_refresh_token =
        add_refresh_token(&mut txn, &session, new_access_token, &refresh_token_str)
            .await
            .wrap_error()?;

    replace_refresh_token(&mut txn, &refresh_token, &new_refresh_token)
        .await
        .wrap_error()?;

    if let Some(access_token) = refresh_token.access_token {
        revoke_access_token(&mut txn, &access_token)
            .await
            .wrap_error()?;
    }

    let params = AccessTokenResponse::new(access_token_str)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token_str)
        .with_scope(session.scope);

    txn.commit().await.wrap_error()?;

    Ok(params)
}
