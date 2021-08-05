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

use data_encoding::BASE64URL_NOPAD;
use itertools::Itertools;
use oauth2_types::{
    pkce,
    requests::{AuthorizationRequest, ResponseType},
};
use serde::Deserialize;
use sqlx::PgPool;
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{session::with_optional_session, with_pool},
    storage::{oauth2::start_session, SessionInfo},
};

#[derive(Deserialize)]
struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::Request>,
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

    let oauth2_session = start_session(
        &mut txn,
        maybe_session_id,
        &client.client_id,
        &scope,
        params.auth.state.as_deref(),
        params.auth.nonce.as_deref(),
    )
    .await
    .wrap_error()?;

    let code = if params.auth.response_type.contains(&ResponseType::Code) {
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

    txn.commit().await.wrap_error()?;

    Ok(warp::reply::json(&serde_json::json!({
        "session": oauth2_session,
        "code": code,
        "redirect_uri": redirect_uri,
    })))
}
