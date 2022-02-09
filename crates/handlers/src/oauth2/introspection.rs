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

use mas_config::{ClientConfig, ClientsConfig, HttpConfig};
use mas_data_model::TokenType;
use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_storage::oauth2::{
    access_token::lookup_active_access_token, refresh_token::lookup_active_refresh_token,
};
use mas_warp_utils::{
    errors::WrapError,
    filters::{self, client::client_authentication, database::connection, url_builder::UrlBuilder},
};
use oauth2_types::requests::{IntrospectionRequest, IntrospectionResponse};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use tracing::{info, warn};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

pub fn filter(
    pool: &PgPool,
    clients_config: &ClientsConfig,
    http_config: &HttpConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let audience = UrlBuilder::from(http_config)
        .oauth_introspection_endpoint()
        .to_string();

    warp::path!("oauth2" / "introspect")
        .and(filters::trace::name("POST /oauth2/introspect"))
        .and(
            warp::post()
                .and(connection(pool))
                .and(client_authentication(clients_config, audience))
                .and_then(introspect)
                .recover(recover)
                .unify(),
        )
        .boxed()
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
    auth: OAuthClientAuthenticationMethod,
    client: ClientConfig,
    params: IntrospectionRequest,
) -> Result<Box<dyn Reply>, Rejection> {
    // Token introspection is only allowed by confidential clients
    if auth == OAuthClientAuthenticationMethod::None {
        warn!(?client, "Client tried to introspect");
        // TODO: have a nice error here
        return Ok(Box::new(warp::reply::json(&INACTIVE)));
    }

    let token = &params.token;
    let token_type = TokenType::check(token).wrap_error()?;
    if let Some(hint) = params.token_type_hint {
        if token_type != hint {
            info!("Token type hint did not match");
            return Ok(Box::new(warp::reply::json(&INACTIVE)));
        }
    }

    let reply = match token_type {
        TokenType::AccessToken => {
            let (token, session) = lookup_active_access_token(&mut conn, token)
                .await
                .wrap_error()?;
            let exp = token.exp();

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: Some(exp),
                iat: Some(token.created_at),
                nbf: Some(token.created_at),
                sub: Some(session.browser_session.user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
        TokenType::RefreshToken => {
            let (token, session) = lookup_active_refresh_token(&mut conn, token)
                .await
                .wrap_error()?;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client.client_id),
                username: Some(session.browser_session.user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
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

    Ok(Box::new(warp::reply::json(&reply)))
}

async fn recover(rejection: Rejection) -> Result<Box<dyn Reply>, Rejection> {
    if rejection.is_not_found() {
        Err(rejection)
    } else {
        Ok(Box::new(warp::reply::json(&INACTIVE)))
    }
}
