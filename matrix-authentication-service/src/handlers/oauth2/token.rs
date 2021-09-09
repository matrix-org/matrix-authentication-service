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
use jwt_compact::{Claims, Header, TimeOptions};
use oauth2_types::{
    errors::{InvalidGrant, OAuth2Error},
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
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{KeySet, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        client::{with_client_auth, ClientAuthentication},
        database::with_connection,
        headers::typed_header,
        with_keys,
    },
    storage::oauth2::{
        access_token::{add_access_token, revoke_access_token},
        authorization_code::lookup_code,
        refresh_token::{add_refresh_token, lookup_refresh_token, replace_refresh_token},
    },
    tokens,
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

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let issuer = oauth2_config.issuer.clone();
    warp::path!("oauth2" / "token")
        .and(warp::post())
        .and(with_client_auth(oauth2_config))
        .and(with_keys(oauth2_config))
        .and(warp::any().map(move || issuer.clone()))
        .and(with_connection(pool))
        .and_then(token)
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
            warp::reply::json(&reply)
        }
        AccessTokenRequest::RefreshToken(grant) => {
            let reply = refresh_token_grant(&grant, &client, &mut conn).await?;
            warp::reply::json(&reply)
        }
        _ => {
            let reply = InvalidGrant.into_response();
            warp::reply::json(&reply)
        }
    };

    Ok(typed_header(
        Pragma::no_cache(),
        typed_header(CacheControl::new().with_no_store(), reply),
    ))
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
    let code = lookup_code(&mut txn, &grant.code).await.wrap_error()?;
    if client.client_id != code.client_id {
        return Err(anyhow::anyhow!("invalid client")).wrap_error();
    }

    // TODO: verify PKCE
    // TODO: make the code invalid
    let ttl = Duration::minutes(5);
    let (access_token, refresh_token) = {
        let mut rng = thread_rng();
        (
            tokens::generate(&mut rng, tokens::TokenType::AccessToken),
            tokens::generate(&mut rng, tokens::TokenType::RefreshToken),
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
        return Err(anyhow::anyhow!("invalid client")).wrap_error();
    }

    let ttl = Duration::minutes(5);
    let (access_token, refresh_token) = {
        let mut rng = thread_rng();
        (
            tokens::generate(&mut rng, tokens::TokenType::AccessToken),
            tokens::generate(&mut rng, tokens::TokenType::RefreshToken),
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
