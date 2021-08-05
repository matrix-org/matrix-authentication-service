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

use std::collections::{HashMap, HashSet};

use data_encoding::BASE64URL_NOPAD;
use headers::HeaderValue;
use hyper::{header::LOCATION, StatusCode};
use itertools::Itertools;
use oauth2_types::{
    pkce,
    requests::{
        AccessTokenResponse, AuthorizationRequest, AuthorizationResponse, ResponseMode,
        ResponseType,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use url::Url;
use warp::{reply::Response, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{session::with_optional_session, with_pool},
    storage::{oauth2::start_session, SessionInfo},
};

struct BackToClient<T> {
    redirect_uri: Url,
    response_mode: ResponseMode,
    params: T,
}

#[derive(Serialize)]
struct AllParams<'s, T> {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    existing: Option<HashMap<&'s str, &'s str>>,

    #[serde(flatten)]
    new: T,
}

impl<T> Reply for BackToClient<T>
where
    T: Serialize + Send,
{
    fn into_response(self) -> warp::reply::Response {
        // TODO: there are a bunch of unwrap here, it might not be the right approach
        let url = match self.response_mode {
            ResponseMode::Query => {
                let mut url = self.redirect_uri;
                let existing: Option<HashMap<&str, &str>> = url
                    .query()
                    .and_then(|qs| serde_urlencoded::from_str(qs).ok());

                let merged = AllParams {
                    existing,
                    new: self.params,
                };

                let new_qs = serde_urlencoded::to_string(merged)
                    .expect("invalid query string serialization");

                url.set_query(Some(&new_qs));
                url
            }
            ResponseMode::Fragment => {
                let mut url = self.redirect_uri;
                let existing: Option<HashMap<&str, &str>> = url
                    .fragment()
                    .and_then(|qs| serde_urlencoded::from_str(qs).ok());

                let merged = AllParams {
                    existing,
                    new: self.params,
                };

                let new_qs = serde_urlencoded::to_string(merged)
                    .expect("invalid query string serialization");

                url.set_fragment(Some(&new_qs));
                url
            }
            ResponseMode::FormPost => todo!(),
        };

        let mut resp = Response::default();
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut().insert(
            LOCATION,
            HeaderValue::from_str(url.as_str()).expect("could not convert url to header value"),
        );
        resp
    }
}

#[derive(Deserialize)]
struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::Request>,
}

fn resolve_response_mode(
    response_type: &HashSet<ResponseType>,
    suggested_response_mode: Option<ResponseMode>,
) -> anyhow::Result<ResponseMode> {
    use ResponseMode as M;
    use ResponseType as T;
    if response_type.contains(&T::Token) || response_type.contains(&T::IdToken) {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(anyhow::anyhow!("invalid response mode")),
            Some(mode) => Ok(mode),
        }
    } else {
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let clients = oauth2_config.clients.clone();
    warp::get()
        .and(warp::path!("oauth2" / "authorize"))
        .map(move || clients.clone())
        .and(warp::query())
        .and(with_optional_session(pool, cookies_config))
        .and(with_pool(pool))
        .and_then(get)
}

async fn get(
    clients: Vec<OAuth2ClientConfig>,
    params: Params,
    maybe_session: Option<SessionInfo>,
    pool: PgPool,
) -> Result<impl Reply, Rejection> {
    // First, find out what client it is
    let client = clients
        .into_iter()
        .find(|client| client.client_id == params.auth.client_id)
        .ok_or_else(|| anyhow::anyhow!("could not find client"))
        .wrap_error()?;

    // Then, figure out the redirect URI
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)
        .wrap_error()?;

    // Start a DB transaction
    let mut txn = pool.begin().await.wrap_error()?;
    let maybe_session_id = maybe_session.as_ref().map(SessionInfo::key);

    let scope: String = {
        let it = params.auth.scope.iter().map(ToString::to_string);
        Itertools::intersperse(it, " ".to_string()).collect()
    };

    let response_type = &params.auth.response_type;
    let response_mode =
        resolve_response_mode(response_type, params.auth.response_mode).wrap_error()?;

    let oauth2_session = start_session(
        &mut txn,
        maybe_session_id,
        &client.client_id,
        &scope,
        params.auth.state.as_deref(),
        params.auth.nonce.as_deref(),
        params.auth.max_age,
        response_type,
        response_mode,
    )
    .await
    .wrap_error()?;

    let code = if response_type.contains(&ResponseType::Code) {
        // 192bit random bytes encoded in base64, which gives a 32 character code
        let code: [u8; 24] = rand::random();
        let code = BASE64URL_NOPAD.encode(&code);
        Some(
            oauth2_session
                .add_code(&mut txn, &code, &params.pkce)
                .await
                .wrap_error()?,
        )
    } else {
        None
    };

    // Do we have a user in this session, with a last authentication time that
    // matches the requirement?
    let user_session = oauth2_session.fetch_session(&mut txn).await.wrap_error()?;
    if let Some(user_session) = user_session {
        if user_session.active && user_session.last_authd_at >= oauth2_session.max_auth_time() {
            // Yep! Let's complete the auth now
            let mut params = AuthorizationResponse {
                state: oauth2_session.state.clone(),
                ..AuthorizationResponse::default()
            };

            // Did they request an auth code?
            if let Some(ref code) = code {
                params.code = Some(code.code.clone());
            }

            // Did they request an access token?
            if response_type.contains(&ResponseType::Token) {
                // TODO: generate and store an access token
                params.access_token = Some(AccessTokenResponse::new(
                    "some_static_token_that_should_be_generated".into(),
                ));
            }

            // Did they request an ID token?
            if response_type.contains(&ResponseType::IdToken) {
                todo!("id tokens are not implemented yet");
            }

            txn.commit().await.wrap_error()?;
            return Ok(BackToClient {
                params,
                response_mode,
                redirect_uri: redirect_uri.clone(),
            }
            .into_response());
        }
        // TODO: show reauth form
    }

    // TODO: show login form

    txn.commit().await.wrap_error()?;
    Ok(warp::reply::json(&serde_json::json!({
        "session": oauth2_session,
        "code": code,
        "redirect_uri": redirect_uri,
    }))
    .into_response())
}
