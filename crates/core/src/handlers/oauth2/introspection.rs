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

use hyper::Method;
use mas_config::{OAuth2ClientConfig, OAuth2Config};
use oauth2_types::requests::{
    ClientAuthenticationMethod, IntrospectionRequest, IntrospectionResponse, TokenTypeHint,
};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use tracing::{info, warn};
use warp::{Filter, Rejection, Reply};

use crate::{
    errors::WrapError,
    filters::{client::client_authentication, cors::cors, database::connection},
    storage::oauth2::{
        access_token::lookup_active_access_token, refresh_token::lookup_active_refresh_token,
    },
    tokens::{self, TokenType},
};

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let audience = oauth2_config
        .issuer
        .join("/oauth2/introspect")
        .unwrap()
        .to_string();

    warp::path!("oauth2" / "introspect").and(
        warp::post()
            .and(connection(pool))
            .and(client_authentication(oauth2_config, audience))
            .and_then(introspect)
            .recover(recover)
            .with(cors().allow_method(Method::POST)),
    )
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
    auth: ClientAuthenticationMethod,
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
            let (token, session) = lookup_active_access_token(&mut conn, token)
                .await
                .wrap_error()?;
            let exp = token.exp();

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(TokenTypeHint::AccessToken),
                exp: Some(exp),
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.browser_session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
        tokens::TokenType::RefreshToken => {
            let (token, session) = lookup_active_refresh_token(&mut conn, token)
                .await
                .wrap_error()?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(TokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.browser_session.user.sub),
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
