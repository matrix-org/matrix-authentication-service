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

use chrono::Duration;
use oauth2_types::{
    errors::{InvalidGrant, OAuth2Error},
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, RefreshTokenGrant,
    },
};
use rand::thread_rng;
use sqlx::{pool::PoolConnection, Acquire, PgPool, Postgres};
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        client::{with_client_auth, ClientAuthentication},
        database::with_connection,
    },
    storage::oauth2::{add_access_token, lookup_code},
    tokens,
};

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("oauth2" / "token")
        .and(warp::post())
        .and(with_client_auth(oauth2_config))
        .and(with_connection(pool))
        .and_then(token)
}

async fn token(
    _auth: ClientAuthentication,
    client: OAuth2ClientConfig,
    req: AccessTokenRequest,
    mut conn: PoolConnection<Postgres>,
) -> Result<impl Reply, Rejection> {
    let reply = match req {
        AccessTokenRequest::AuthorizationCode(grant) => {
            let reply = authorization_code_grant(&grant, &client, &mut conn).await?;
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

    Ok(reply)
}

async fn authorization_code_grant(
    grant: &AuthorizationCodeGrant,
    client: &OAuth2ClientConfig,
    conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    let mut txn = conn.begin().await.wrap_error()?;
    let code = lookup_code(&mut txn, &grant.code).await.wrap_error()?;
    if client.client_id != code.client_id {
        return Err(anyhow::anyhow!("invalid client"))
            .wrap_error()
            .map_err(warp::reject::custom);
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

    add_access_token(&mut txn, code.oauth2_session_id, &access_token, ttl)
        .await
        .wrap_error()?;
    // TODO: save the refresh token

    // TODO: generate id_token if the "openid" scope was asked
    // TODO: have the scopes back here
    let params = AccessTokenResponse::new(access_token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token);

    txn.commit().await.wrap_error()?;

    Ok(params)
}

async fn refresh_token_grant(
    _grant: &RefreshTokenGrant,
    _client: &OAuth2ClientConfig,
    _conn: &mut PoolConnection<Postgres>,
) -> Result<AccessTokenResponse, Rejection> {
    todo!()
}
