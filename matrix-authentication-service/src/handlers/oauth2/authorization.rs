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

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
};

use chrono::Duration;
use data_encoding::BASE64URL_NOPAD;
use hyper::{
    header::LOCATION,
    http::uri::{Parts, PathAndQuery, Uri},
    StatusCode,
};
use itertools::Itertools;
use oauth2_types::{
    pkce,
    requests::{
        AccessTokenResponse, AuthorizationRequest, AuthorizationResponse, ResponseMode,
        ResponseType,
    },
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use url::Url;
use warp::{
    redirect::see_other,
    reply::{html, with_header},
    Filter, Rejection, Reply,
};

use crate::{
    config::{CookiesConfig, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        database::with_transaction,
        session::{with_optional_session, with_session},
        with_templates,
    },
    handlers::views::LoginRequest,
    storage::{
        oauth2::{
            access_token::add_access_token,
            refresh_token::add_refresh_token,
            session::{get_session_by_id, start_session},
        },
        SessionInfo,
    },
    templates::{FormPostContext, Templates},
    tokens,
};

fn back_to_client<T>(
    mut redirect_uri: Url,
    response_mode: ResponseMode,
    params: T,
    templates: &Templates,
) -> anyhow::Result<Box<dyn Reply>>
where
    T: Serialize,
{
    #[derive(Serialize)]
    struct AllParams<'s, T> {
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        existing: Option<HashMap<&'s str, &'s str>>,

        #[serde(flatten)]
        params: T,
    }

    match response_mode {
        ResponseMode::Query => {
            let existing: Option<HashMap<&str, &str>> = redirect_uri
                .query()
                .map(|qs| serde_urlencoded::from_str(qs))
                .transpose()?;

            let merged = AllParams { existing, params };

            let new_qs = serde_urlencoded::to_string(merged)?;

            redirect_uri.set_query(Some(&new_qs));

            Ok(Box::new(with_header(
                StatusCode::SEE_OTHER,
                LOCATION,
                redirect_uri.as_str(),
            )))
        }
        ResponseMode::Fragment => {
            let existing: Option<HashMap<&str, &str>> = redirect_uri
                .fragment()
                .map(|qs| serde_urlencoded::from_str(qs))
                .transpose()?;

            let merged = AllParams { existing, params };

            let new_qs = serde_urlencoded::to_string(merged)?;

            redirect_uri.set_fragment(Some(&new_qs));

            Ok(Box::new(with_header(
                StatusCode::SEE_OTHER,
                LOCATION,
                redirect_uri.as_str(),
            )))
        }
        ResponseMode::FormPost => {
            let ctx = FormPostContext::new(redirect_uri, params);
            let rendered = templates.render_form_post(&ctx)?;
            Ok(Box::new(html(rendered)))
        }
    }
}

#[derive(Deserialize)]
struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::Request>,
}

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
fn resolve_response_mode(
    response_type: &HashSet<ResponseType>,
    suggested_response_mode: Option<ResponseMode>,
) -> anyhow::Result<ResponseMode> {
    use ResponseMode as M;
    use ResponseType as T;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.contains(&T::Token) || response_type.contains(&T::IdToken) {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(anyhow::anyhow!("invalid response mode")),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

pub fn filter(
    pool: &PgPool,
    templates: &Templates,
    oauth2_config: &OAuth2Config,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let clients = oauth2_config.clients.clone();
    let authorize = warp::path!("oauth2" / "authorize")
        .and(warp::get())
        .map(move || clients.clone())
        .and(warp::query())
        .and(with_optional_session(pool, cookies_config))
        .and(with_transaction(pool))
        .and(with_templates(templates))
        .and_then(get);

    let step = warp::path!("oauth2" / "authorize" / "step")
        .and(warp::get())
        .and(warp::query().map(|s: StepRequest| s.id))
        .and(with_session(pool, cookies_config))
        .and(with_transaction(pool))
        .and(with_templates(templates))
        .and_then(step);

    authorize.or(step)
}

async fn get(
    clients: Vec<OAuth2ClientConfig>,
    params: Params,
    maybe_session: Option<SessionInfo>,
    mut txn: Transaction<'_, Postgres>,
    templates: Templates,
) -> Result<Box<dyn Reply>, Rejection> {
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
        redirect_uri,
        &scope,
        params.auth.state.as_deref(),
        params.auth.nonce.as_deref(),
        params.auth.max_age,
        response_type,
        response_mode,
    )
    .await
    .wrap_error()?;

    // Generate the code at this stage, since we have the PKCE params ready
    if response_type.contains(&ResponseType::Code) {
        // 192bit random bytes encoded in base64, which gives a 32 character code
        let code: [u8; 24] = rand::random();
        let code = BASE64URL_NOPAD.encode(&code);
        oauth2_session
            .add_code(&mut txn, &code, &params.pkce)
            .await
            .wrap_error()?;
    };

    // Do we already have a user session for this oauth2 session?
    let user_session = oauth2_session.fetch_session(&mut txn).await.wrap_error()?;

    if let Some(user_session) = user_session {
        step(oauth2_session.id, user_session, txn, templates).await
    } else {
        // If not, redirect the user to the login page
        txn.commit().await.wrap_error()?;

        let next = StepRequest::new(oauth2_session.id)
            .build_uri()
            .wrap_error()?
            .to_string();

        let destination = LoginRequest::new(Some(next)).build_uri().wrap_error()?;
        Ok(Box::new(see_other(destination)))
    }
}

#[derive(Deserialize, Serialize)]
struct StepRequest {
    id: i64,
}

impl StepRequest {
    fn new(id: i64) -> Self {
        Self { id }
    }

    fn build_uri(&self) -> anyhow::Result<Uri> {
        let qs = serde_urlencoded::to_string(self)?;
        let path_and_query = PathAndQuery::try_from(format!("/oauth2/authorize/step?{}", qs))?;
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }
}

async fn step(
    oauth2_session_id: i64,
    user_session: SessionInfo,
    mut txn: Transaction<'_, Postgres>,
    templates: Templates,
) -> Result<Box<dyn Reply>, Rejection> {
    let mut oauth2_session = get_session_by_id(&mut txn, oauth2_session_id)
        .await
        .wrap_error()?;

    let user_session = oauth2_session
        .match_or_set_session(&mut txn, user_session)
        .await
        .wrap_error()?;

    let response_mode = oauth2_session.response_mode().wrap_error()?;
    let response_type = oauth2_session.response_type().wrap_error()?;
    let redirect_uri = oauth2_session.redirect_uri().wrap_error()?;

    // Check if the active session is valid
    let reply = if user_session.active
        && user_session.last_authd_at >= oauth2_session.max_auth_time()
    {
        // Yep! Let's complete the auth now
        let mut params = AuthorizationResponse {
            state: oauth2_session.state.clone(),
            ..AuthorizationResponse::default()
        };

        // Did they request an auth code?
        if response_type.contains(&ResponseType::Code) {
            params.code = Some(oauth2_session.fetch_code(&mut txn).await.wrap_error()?);
        }

        // Did they request an access token?
        if response_type.contains(&ResponseType::Token) {
            let ttl = Duration::minutes(5);
            let (access_token, refresh_token) = {
                let mut rng = thread_rng();
                (
                    tokens::generate(&mut rng, tokens::TokenType::AccessToken),
                    tokens::generate(&mut rng, tokens::TokenType::RefreshToken),
                )
            };

            let access_token = add_access_token(&mut txn, oauth2_session_id, &access_token, ttl)
                .await
                .wrap_error()?;

            let refresh_token =
                add_refresh_token(&mut txn, oauth2_session_id, access_token.id, &refresh_token)
                    .await
                    .wrap_error()?;

            params.response = Some(
                AccessTokenResponse::new(access_token.token)
                    .with_expires_in(ttl)
                    .with_refresh_token(refresh_token.token),
            );
        }

        // Did they request an ID token?
        if response_type.contains(&ResponseType::IdToken) {
            todo!("id tokens are not implemented yet");
        }

        back_to_client(redirect_uri, response_mode, params, &templates).wrap_error()?
    } else {
        // Ask for a reauth
        // TODO: have the OAuth2 session ID in there
        Box::new(see_other(Uri::from_static("/reauth")))
    };

    txn.commit().await.wrap_error()?;
    Ok(reply)
}
