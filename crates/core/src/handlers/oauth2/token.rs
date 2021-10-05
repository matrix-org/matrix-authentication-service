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

use anyhow::Context;
use chrono::Duration;
use data_encoding::BASE64URL_NOPAD;
use headers::{CacheControl, Pragma};
use hyper::StatusCode;
use jwt_compact::{Claims, Header, TimeOptions};
use oauth2_types::{
    errors::{
        InvalidGrant, InvalidRequest, OAuth2Error, OAuth2ErrorCode, ServerError, UnauthorizedClient,
    },
    pkce::CodeChallengeMethod,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, RefreshTokenGrant,
    },
};
use rand::thread_rng;
use serde::Serialize;
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use sqlx::{pool::PoolConnection, Acquire, PgPool, Postgres};
use url::Url;
use warp::{
    reject::Reject,
    reply::{json, with_status},
    Filter, Rejection, Reply,
};

use crate::{
    config::{KeySet, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        client::{client_authentication, ClientAuthentication},
        database::connection,
        with_keys,
    },
    reply::with_typed_header,
    storage::oauth2::{
        access_token::{add_access_token, revoke_access_token},
        authorization_code::{consume_code, lookup_code},
        refresh_token::{add_refresh_token, lookup_refresh_token, replace_refresh_token},
    },
    tokens::{AccessToken, RefreshToken},
};

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
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let issuer = oauth2_config.issuer.clone();
    warp::path!("oauth2" / "token")
        .and(warp::post())
        .and(client_authentication(oauth2_config))
        .and(with_keys(oauth2_config))
        .and(warp::any().map(move || issuer.clone()))
        .and(connection(pool))
        .and_then(token)
        .recover(recover)
}

async fn recover(rejection: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(Error { json, status }) = rejection.find::<Error>() {
        Ok(with_status(warp::reply::json(json), *status))
    } else {
        Err(rejection)
    }
}

async fn token(
    _auth: ClientAuthentication,
    client: OAuth2ClientConfig,
    req: AccessTokenRequest,
    keys: KeySet,
    issuer: Url,
    mut conn: PoolConnection<Postgres>,
) -> Result<impl Reply, Rejection> {
    let reply = match req {
        AccessTokenRequest::AuthorizationCode(grant) => {
            let reply = authorization_code_grant(&grant, &client, &keys, issuer, &mut conn).await?;
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
    Ok(reply)
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

async fn authorization_code_grant(
    grant: &AuthorizationCodeGrant,
    client: &OAuth2ClientConfig,
    keys: &KeySet,
    issuer: Url,
    conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    let mut txn = conn.begin().await.wrap_error()?;

    // TODO: we should invalidate the existing session if a code is used twice after
    // some period of time. See the `oidcc-codereuse-30seconds` test from the
    // conformance suite
    let code = match lookup_code(&mut txn, &grant.code).await {
        Err(e) if e.not_found() => return error(InvalidGrant),
        x => x,
    }?;

    if client.client_id != code.client_id {
        return error(UnauthorizedClient);
    }

    match (
        code.code_challenge_method.as_ref(),
        code.code_challenge.as_ref(),
        grant.code_verifier.as_ref(),
    ) {
        (None, None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), Some(_), None) | (None, None, Some(_)) => return error(InvalidRequest),
        (Some(0 /* Plain */), Some(code_challenge), Some(code_verifier)) => {
            if !CodeChallengeMethod::Plain.verify(code_challenge, code_verifier) {
                return error(InvalidRequest);
            }
        }
        (Some(1 /* S256 */), Some(code_challenge), Some(code_verifier)) => {
            if !CodeChallengeMethod::S256.verify(code_challenge, code_verifier) {
                return error(InvalidRequest);
            }
        }

        // We have something else?
        // That's a DB inconcistancy, we should bail out
        _ => {
            // TODO: are we sure we want to handle errors like that?
            tracing::error!("Invalid state from the database");
            return error(ServerError); // Somthing bad happened in the database
        }
    };

    // TODO: verify PKCE
    let ttl = Duration::minutes(5);
    let (access_token, refresh_token) = {
        let mut rng = thread_rng();
        (
            AccessToken.generate(&mut rng),
            RefreshToken.generate(&mut rng),
        )
    };

    let access_token = add_access_token(&mut txn, code.oauth2_session_id, &access_token, ttl)
        .await
        .wrap_error()?;

    let refresh_token = add_refresh_token(
        &mut txn,
        code.oauth2_session_id,
        access_token.id,
        &refresh_token,
    )
    .await
    .wrap_error()?;

    // TODO: generate id_token only if the "openid" scope was asked
    let header = Header::default();
    let options = TimeOptions::default();
    let claims = Claims::new(CustomClaims {
        issuer,
        // TODO: get that from the session
        subject: "random-subject".to_string(),
        audiences: vec![client.client_id.clone()],
        nonce: code.nonce,
        at_hash: hash(Sha256::new(), &access_token.token).wrap_error()?,
        c_hash: hash(Sha256::new(), &grant.code).wrap_error()?,
    })
    .set_duration_and_issuance(&options, Duration::minutes(30));
    let id_token = keys
        .token(crate::config::Algorithm::Rs256, header, claims)
        .await
        .context("could not sign ID token")
        .wrap_error()?;

    // TODO: have the scopes back here
    let params = AccessTokenResponse::new(access_token.token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.token)
        .with_id_token(id_token);

    consume_code(&mut txn, code.id).await.wrap_error()?;

    txn.commit().await.wrap_error()?;

    Ok(params)
}

async fn refresh_token_grant(
    grant: &RefreshTokenGrant,
    client: &OAuth2ClientConfig,
    conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    let mut txn = conn.begin().await.wrap_error()?;
    // TODO: scope handling
    let refresh_token_lookup = lookup_refresh_token(&mut txn, &grant.refresh_token)
        .await
        .wrap_error()?;

    if client.client_id != refresh_token_lookup.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return error(InvalidGrant);
    }

    let ttl = Duration::minutes(5);
    let (access_token, refresh_token) = {
        let mut rng = thread_rng();
        (
            AccessToken.generate(&mut rng),
            RefreshToken.generate(&mut rng),
        )
    };

    let access_token = add_access_token(
        &mut txn,
        refresh_token_lookup.oauth2_session_id,
        &access_token,
        ttl,
    )
    .await
    .wrap_error()?;

    let refresh_token = add_refresh_token(
        &mut txn,
        refresh_token_lookup.oauth2_session_id,
        access_token.id,
        &refresh_token,
    )
    .await
    .wrap_error()?;

    replace_refresh_token(&mut txn, refresh_token_lookup.id, refresh_token.id)
        .await
        .wrap_error()?;

    if let Some(access_token_id) = refresh_token_lookup.oauth2_access_token_id {
        revoke_access_token(&mut txn, access_token_id)
            .await
            .wrap_error()?;
    }

    let params = AccessTokenResponse::new(access_token.token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.token);

    txn.commit().await.wrap_error()?;

    Ok(params)
}
