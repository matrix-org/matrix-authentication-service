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
use hyper::{
    header::LOCATION,
    http::uri::{Parts, PathAndQuery, Uri},
    StatusCode,
};
use mas_data_model::{
    Authentication, AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, BrowserSession,
    Pkce, StorageBackend,
};
use mas_templates::{FormPostContext, Templates};
use oauth2_types::{
    errors::{ErrorResponse, InvalidGrant, InvalidRequest, OAuth2Error},
    pkce,
    requests::{
        AccessTokenResponse, AuthorizationRequest, AuthorizationResponse, ResponseMode,
        ResponseType,
    },
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use url::Url;
use warp::{
    redirect::see_other,
    reject::InvalidQuery,
    reply::{html, with_header},
    Filter, Rejection, Reply,
};

use crate::{
    config::{CookiesConfig, OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
    filters::{
        database::transaction,
        session::{optional_session, session},
        with_templates,
    },
    handlers::views::{LoginRequest, PostAuthAction, ReauthRequest},
    storage::{
        oauth2::{
            access_token::add_access_token,
            authorization_grant::{
                derive_session, fulfill_grant, get_grant_by_id, new_authorization_grant,
            },
            refresh_token::add_refresh_token,
        },
        PostgresqlBackend,
    },
    tokens::{AccessToken, RefreshToken},
};

#[derive(Deserialize)]
struct PartialParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    /*
    response_type: Option<String>,
    response_mode: Option<String>,
    */
}

enum ReplyOrBackToClient {
    Reply(Box<dyn Reply>),
    BackToClient {
        params: Value,
        redirect_uri: Url,
        response_mode: ResponseMode,
        state: Option<String>,
    },
    Error(Box<dyn OAuth2Error>),
}

fn back_to_client<T>(
    mut redirect_uri: Url,
    response_mode: ResponseMode,
    state: Option<String>,
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

        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<String>,

        #[serde(flatten)]
        params: T,
    }

    #[derive(Serialize)]
    struct ParamsWithState<T> {
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<String>,

        #[serde(flatten)]
        params: T,
    }

    match response_mode {
        ResponseMode::Query => {
            let existing: Option<HashMap<&str, &str>> = redirect_uri
                .query()
                .map(|qs| serde_urlencoded::from_str(qs))
                .transpose()?;

            let merged = AllParams {
                existing,
                state,
                params,
            };

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

            let merged = AllParams {
                existing,
                state,
                params,
            };

            let new_qs = serde_urlencoded::to_string(merged)?;

            redirect_uri.set_fragment(Some(&new_qs));

            Ok(Box::new(with_header(
                StatusCode::SEE_OTHER,
                LOCATION,
                redirect_uri.as_str(),
            )))
        }
        ResponseMode::FormPost => {
            let merged = ParamsWithState { state, params };
            let ctx = FormPostContext::new(redirect_uri, merged);
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
    pkce: Option<pkce::AuthorizationRequest>,
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
        .and(optional_session(pool, cookies_config))
        .and(transaction(pool))
        .and_then(get);

    let step = warp::path!("oauth2" / "authorize" / "step")
        .and(warp::get())
        .and(warp::query())
        .and(session(pool, cookies_config))
        .and(transaction(pool))
        .and_then(step);

    let clients = oauth2_config.clients.clone();
    authorize
        .or(step)
        .unify()
        .recover(recover)
        .unify()
        .and(warp::query())
        .and(warp::any().map(move || clients.clone()))
        .and(with_templates(templates))
        .and_then(actually_reply)
}

async fn recover(rejection: Rejection) -> Result<ReplyOrBackToClient, Rejection> {
    if rejection.find::<InvalidQuery>().is_some() {
        Ok(ReplyOrBackToClient::Error(Box::new(InvalidRequest)))
    } else {
        Err(rejection)
    }
}

async fn actually_reply(
    rep: ReplyOrBackToClient,
    q: PartialParams,
    clients: Vec<OAuth2ClientConfig>,
    templates: Templates,
) -> Result<impl Reply, Rejection> {
    let (redirect_uri, response_mode, state, params) = match rep {
        ReplyOrBackToClient::Reply(r) => return Ok(r),
        ReplyOrBackToClient::BackToClient {
            redirect_uri,
            response_mode,
            params,
            state,
        } => (redirect_uri, response_mode, state, params),
        ReplyOrBackToClient::Error(error) => {
            let PartialParams {
                client_id,
                redirect_uri,
                state,
                ..
            } = q;

            // First, disover the client
            let client = client_id.and_then(|client_id| {
                clients
                    .into_iter()
                    .find(|client| client.client_id == client_id)
            });

            let client = match client {
                Some(client) => client,
                None => return Ok(Box::new(html(templates.render_error(&error.into())?))),
            };

            let redirect_uri: Result<Option<Url>, _> = redirect_uri.map(|r| r.parse()).transpose();
            let redirect_uri = match redirect_uri {
                Ok(r) => r,
                Err(_) => return Ok(Box::new(html(templates.render_error(&error.into())?))),
            };

            let redirect_uri = client.resolve_redirect_uri(&redirect_uri);
            let redirect_uri = match redirect_uri {
                Ok(r) => r,
                Err(_) => return Ok(Box::new(html(templates.render_error(&error.into())?))),
            };

            let reply: ErrorResponse = error.into();
            let reply = serde_json::to_value(&reply).wrap_error()?;
            // TODO: resolve response mode
            (redirect_uri.clone(), ResponseMode::Query, state, reply)
        }
    };

    back_to_client(redirect_uri, response_mode, state, params, &templates).wrap_error()
}

async fn get(
    clients: Vec<OAuth2ClientConfig>,
    params: Params,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
    mut txn: Transaction<'_, Postgres>,
) -> Result<ReplyOrBackToClient, Rejection> {
    // First, find out what client it is
    let client = clients
        .into_iter()
        .find(|client| client.client_id == params.auth.client_id)
        .ok_or_else(|| anyhow::anyhow!("could not find client"))
        .wrap_error()?;

    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)
        .wrap_error()?;
    let response_type = &params.auth.response_type;
    let response_mode =
        resolve_response_mode(response_type, params.auth.response_mode).wrap_error()?;

    let code: Option<AuthorizationCode> = if response_type.contains(&ResponseType::Code) {
        // 32 random alphanumeric characters, about 190bit of entropy
        let code: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let pkce = params.pkce.map(|p| Pkce {
            challenge: p.code_challenge,
            challenge_method: p.code_challenge_method,
        });

        Some(AuthorizationCode { code, pkce })
    } else {
        // If the request had PKCE params but no code asked, it should get back with an
        // error
        if params.pkce.is_some() {
            return Ok(ReplyOrBackToClient::Error(Box::new(InvalidGrant)));
        }

        None
    };

    let grant = new_authorization_grant(
        &mut txn,
        client.client_id.clone(),
        redirect_uri.clone(),
        params.auth.scope,
        code,
        params.auth.state,
        params.auth.nonce,
        params.auth.max_age,
        None,
        response_mode,
        response_type.contains(&ResponseType::Token),
        response_type.contains(&ResponseType::IdToken),
    )
    .await
    .wrap_error()?;

    let next = ContinueAuthorizationGrant::from_authorization_grant(grant);

    if let Some(user_session) = maybe_session {
        step(next, user_session, txn).await
    } else {
        // If not, redirect the user to the login page
        txn.commit().await.wrap_error()?;

        let next: PostAuthAction<_> = next.into();
        let next: LoginRequest<_> = next.into();
        let next = next.build_uri().wrap_error()?;

        Ok(ReplyOrBackToClient::Reply(Box::new(see_other(next))))
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ContinueAuthorizationGrant<S: StorageBackend> {
    #[serde(
        with = "serde_with::rust::display_fromstr",
        bound(
            deserialize = "S::AuthorizationGrantData: std::str::FromStr, 
                           <S::AuthorizationGrantData as std::str::FromStr>::Err: std::fmt::Display",
            serialize = "S::AuthorizationGrantData: std::fmt::Display"
        )
    )]
    data: S::AuthorizationGrantData,
}

impl<S: StorageBackend> ContinueAuthorizationGrant<S> {
    pub fn from_authorization_grant(grant: AuthorizationGrant<S>) -> Self {
        Self { data: grant.data }
    }

    pub fn build_uri(&self) -> anyhow::Result<Uri>
    where
        S::AuthorizationGrantData: std::fmt::Display,
    {
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

impl ContinueAuthorizationGrant<PostgresqlBackend> {
    pub async fn fetch_authorization_grant(
        &self,
        executor: impl PgExecutor<'_>,
    ) -> anyhow::Result<AuthorizationGrant<PostgresqlBackend>> {
        get_grant_by_id(executor, self.data).await
    }
}

async fn step(
    next: ContinueAuthorizationGrant<PostgresqlBackend>,
    browser_session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
) -> Result<ReplyOrBackToClient, Rejection> {
    // TODO: we should check if the grant here was started by the browser doing that
    // request using a signed cookie
    let grant = next
        .fetch_authorization_grant(&mut txn)
        .await
        .wrap_error()?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(anyhow::anyhow!("authorization grant not pending")).wrap_error();
    }

    let reply = match browser_session.last_authentication {
        Some(Authentication { created_at, .. }) if created_at > grant.max_auth_time() => {
            let session = derive_session(&mut txn, &grant, browser_session)
                .await
                .wrap_error()?;

            let grant = fulfill_grant(&mut txn, grant, session.clone())
                .await
                .wrap_error()?;

            // Yep! Let's complete the auth now
            let mut params = AuthorizationResponse::default();

            // Did they request an auth code?
            if let Some(code) = grant.code {
                params.code = Some(code.code);
            }

            // Did they request an access token?
            if grant.response_type_token {
                let ttl = Duration::minutes(5);
                let (access_token_str, refresh_token_str) = {
                    let mut rng = thread_rng();
                    (
                        AccessToken.generate(&mut rng),
                        RefreshToken.generate(&mut rng),
                    )
                };

                let access_token = add_access_token(&mut txn, &session, &access_token_str, ttl)
                    .await
                    .wrap_error()?;

                let _refresh_token =
                    add_refresh_token(&mut txn, &session, access_token, &refresh_token_str)
                        .await
                        .wrap_error()?;

                params.response = Some(
                    AccessTokenResponse::new(access_token_str)
                        .with_expires_in(ttl)
                        .with_refresh_token(refresh_token_str),
                );
            }

            // Did they request an ID token?
            if grant.response_type_id_token {
                todo!("id tokens are not implemented yet");
            }

            let params = serde_json::to_value(&params).unwrap();
            ReplyOrBackToClient::BackToClient {
                redirect_uri: grant.redirect_uri,
                response_mode: grant.response_mode,
                state: grant.state,
                params,
            }
        }
        _ => {
            let next: PostAuthAction<_> = next.into();
            let next: ReauthRequest<_> = next.into();
            let next = next.build_uri().wrap_error()?;

            ReplyOrBackToClient::Reply(Box::new(see_other(next)))
        }
    };

    txn.commit().await.wrap_error()?;
    Ok(reply)
}
