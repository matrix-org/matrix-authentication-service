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

use chrono::Utc;
use oauth2_types::requests::{IntrospectionRequest, IntrospectionResponse, TokenTypeHint};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use tracing::{info, warn};
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        client::{client_authentication, ClientAuthentication},
        database::connection,
    },
    storage::oauth2::{access_token::lookup_access_token, refresh_token::lookup_refresh_token},
    tokens::{self, TokenType},
};

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("oauth2" / "introspect")
        .and(warp::post())
        .and(connection(pool))
        .and(client_authentication(oauth2_config))
        .and_then(introspect)
        .recover(recover)
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

async fn introspect(
    mut conn: PoolConnection<Postgres>,
    auth: ClientAuthentication,
    client: OAuth2ClientConfig,
    params: IntrospectionRequest,
) -> Result<impl Reply, Rejection> {
    // Token introspection is only allowed by confidential clients
    if auth.public() {
        warn!(?client, "Client tried to introspect");
        // TODO: have a nice error here
        return Ok(warp::reply::json(&INACTIVE));
    }

    let token = &params.token;
    let token_type = TokenType::check(token).wrap_error()?;
    if let Some(hint) = params.token_type_hint {
        if token_type != hint {
            info!("Token type hint did not match");
            return Ok(warp::reply::json(&INACTIVE));
        }
    }

    let reply = match token_type {
        tokens::TokenType::AccessToken => {
            let token = lookup_access_token(&mut conn, token).await.wrap_error()?;
            let exp = token.exp();

            // Check it is active and did not expire
            if !token.active || exp < Utc::now() {
                info!(?token, "Access token expired");
                return Ok(warp::reply::json(&INACTIVE));
            }

            IntrospectionResponse {
                active: true,
                scope: None, // TODO: parse back scopes
                client_id: Some(token.client_id.clone()),
                username: Some(token.username.clone()),
                token_type: Some(TokenTypeHint::AccessToken),
                exp: Some(exp),
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }
        }
        tokens::TokenType::RefreshToken => {
            let token = lookup_refresh_token(&mut conn, token).await.wrap_error()?;

            IntrospectionResponse {
                active: true,
                scope: None, // TODO: parse back scopes
                client_id: Some(token.client_id),
                username: None,
                token_type: Some(TokenTypeHint::RefreshToken),
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }
        }
    };

    Ok(warp::reply::json(&reply))
}

async fn recover(rejection: Rejection) -> Result<impl Reply, Rejection> {
    if rejection.is_not_found() {
        Err(rejection)
    } else {
        Ok(warp::reply::json(&INACTIVE))
    }
}
