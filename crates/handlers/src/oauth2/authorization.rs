// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::collections::HashMap;

use anyhow::Context;
use axum::{
    extract::{Extension, Form, Query},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::Duration;
use hyper::{
    http::uri::{Parts, PathAndQuery, Uri},
    StatusCode,
};
use mas_axum_utils::{PrivateCookieJar, SessionInfoExt};
use mas_config::Encrypter;
use mas_data_model::{
    Authentication, AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, BrowserSession,
    Pkce, StorageBackend, TokenType,
};
use mas_iana::oauth::OAuthAuthorizationEndpointResponseType;
use mas_storage::{
    oauth2::{
        access_token::add_access_token,
        authorization_grant::{
            derive_session, fulfill_grant, get_grant_by_id, new_authorization_grant,
        },
        client::{lookup_client_by_client_id, ClientFetchError},
        refresh_token::add_refresh_token,
    },
    PostgresqlBackend,
};
use mas_templates::{FormPostContext, Templates};
use oauth2_types::{
    errors::{
        INVALID_REQUEST, LOGIN_REQUIRED, REGISTRATION_NOT_SUPPORTED, REQUEST_NOT_SUPPORTED,
        REQUEST_URI_NOT_SUPPORTED, UNAUTHORIZED_CLIENT,
    },
    pkce,
    prelude::*,
    requests::{
        AccessTokenResponse, AuthorizationRequest, AuthorizationResponse, GrantType, Prompt,
        ResponseMode,
    },
    scope::ScopeToken,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use thiserror::Error;
use url::Url;

use crate::views::{LoginRequest, PostAuthAction, ReauthRequest, RegisterRequest};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Anyhow(anyhow::Error),
    #[error("could not find client")]
    ClientNotFound,
    #[error("invalid redirect uri")]
    InvalidRedirectUri,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<ClientFetchError> for RouteError {
    fn from(e: ClientFetchError) -> Self {
        if e.not_found() {
            Self::ClientNotFound
        } else {
            Self::Internal(Box::new(e))
        }
    }
}

impl From<anyhow::Error> for RouteError {
    fn from(e: anyhow::Error) -> Self {
        Self::Anyhow(e)
    }
}

async fn back_to_client<T>(
    redirect_uri: &Url,
    response_mode: ResponseMode,
    state: Option<String>,
    params: T,
    templates: &Templates,
) -> Result<Response, RouteError>
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

    let mut redirect_uri = redirect_uri.clone();

    match response_mode {
        ResponseMode::Query => {
            let existing: Option<HashMap<&str, &str>> = redirect_uri
                .query()
                .map(serde_urlencoded::from_str)
                .transpose()
                .map_err(|_e| RouteError::InvalidRedirectUri)?;

            let merged = AllParams {
                existing,
                state,
                params,
            };

            let new_qs = serde_urlencoded::to_string(merged)
                .context("could not serialize redirect URI query params")?;

            redirect_uri.set_query(Some(&new_qs));

            Ok(Redirect::to(redirect_uri.as_str()).into_response())
        }
        ResponseMode::Fragment => {
            let existing: Option<HashMap<&str, &str>> = redirect_uri
                .fragment()
                .map(serde_urlencoded::from_str)
                .transpose()
                .map_err(|_e| RouteError::InvalidRedirectUri)?;

            let merged = AllParams {
                existing,
                state,
                params,
            };

            let new_qs = serde_urlencoded::to_string(merged)
                .context("could not serialize redirect URI fragment params")?;

            redirect_uri.set_fragment(Some(&new_qs));

            Ok(Redirect::to(redirect_uri.as_str()).into_response())
        }
        ResponseMode::FormPost => {
            let merged = ParamsWithState { state, params };
            let ctx = FormPostContext::new(redirect_uri, merged);
            let rendered = templates
                .render_form_post(&ctx)
                .await
                .context("failed to render form_post.html")?;
            Ok(Html(rendered).into_response())
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
fn resolve_response_mode(
    response_type: OAuthAuthorizationEndpointResponseType,
    suggested_response_mode: Option<ResponseMode>,
) -> anyhow::Result<ResponseMode> {
    use ResponseMode as M;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.has_token() || response_type.has_id_token() {
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

#[allow(clippy::too_many_lines)]
#[tracing::instrument(skip_all, err)]
pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(params): Form<Params>,
) -> Result<Response, RouteError> {
    let mut txn = pool.begin().await?;

    // First, fetch the current session if there is one
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut txn)
        .await
        .context("failed to load browser session")?;

    // Then, find out what client it is
    let client = lookup_client_by_client_id(&mut txn, &params.auth.client_id).await?;

    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)
        .map_err(|_e| RouteError::InvalidRedirectUri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(response_type, params.auth.response_mode)?;

    // One day, we will have try blocks
    let res: Result<Response, RouteError> = (async move {
        // Check if the request/request_uri/registration params are used. If so, reply
        // with the right error since we don't support them.
        if params.auth.request.is_some() {
            return back_to_client(
                &redirect_uri,
                response_mode,
                params.auth.state,
                REQUEST_NOT_SUPPORTED,
                &templates,
            )
            .await;
        }

        if params.auth.request_uri.is_some() {
            return back_to_client(
                &redirect_uri,
                response_mode,
                params.auth.state,
                REQUEST_URI_NOT_SUPPORTED,
                &templates,
            )
            .await;
        }

        if params.auth.registration.is_some() {
            return back_to_client(
                &redirect_uri,
                response_mode,
                params.auth.state,
                REGISTRATION_NOT_SUPPORTED,
                &templates,
            )
            .await;
        }

        // Check if it is allowed to use this grant type
        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return back_to_client(
                &redirect_uri,
                response_mode,
                params.auth.state,
                UNAUTHORIZED_CLIENT,
                &templates,
            )
            .await;
        }

        let code: Option<AuthorizationCode> = if response_type.has_code() {
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
                return back_to_client(
                    &redirect_uri,
                    response_mode,
                    params.auth.state,
                    INVALID_REQUEST,
                    &templates,
                )
                .await;
            }

            None
        };

        // Generate the device ID
        // TODO: this should probably be done somewhere else?
        let device_id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let device_scope: ScopeToken = format!("urn:matrix:device:{}", device_id)
            .parse()
            .context("could not parse generated device scope")?;

        let scope = {
            let mut s = params.auth.scope.clone();
            s.insert(device_scope);
            s
        };

        let grant = new_authorization_grant(
            &mut txn,
            client,
            redirect_uri.clone(),
            scope,
            code,
            params.auth.state.clone(),
            params.auth.nonce,
            params.auth.max_age,
            None,
            response_mode,
            response_type.has_token(),
            response_type.has_id_token(),
        )
        .await?;

        let next = ContinueAuthorizationGrant::from_authorization_grant(&grant);

        match (maybe_session, params.auth.prompt) {
            (None, Some(Prompt::None)) => {
                // If there is no session and prompt=none was asked, go back to the client
                txn.commit().await?;
                Ok(back_to_client(
                    &redirect_uri,
                    response_mode,
                    params.auth.state,
                    LOGIN_REQUIRED,
                    &templates,
                )
                .await?)
            }
            (Some(_), Some(Prompt::Login | Prompt::Consent | Prompt::SelectAccount)) => {
                // We're already logged in but login|consent|select_account was asked, reauth
                // TODO: better pages here
                txn.commit().await?;

                let next: PostAuthAction = next.into();
                let next: ReauthRequest = next.into();
                let next = next.build_uri()?;

                Ok(Redirect::to(&next.to_string()).into_response())
            }
            (Some(user_session), _) => {
                // Other cases where we already have a session
                step(next, user_session, txn, &templates).await
            }
            (None, Some(Prompt::Create)) => {
                // Client asked for a registration, show the registration prompt
                txn.commit().await?;

                let next: PostAuthAction = next.into();
                let next: RegisterRequest = next.into();
                let next = next.build_uri()?;

                Ok(Redirect::to(&next.to_string()).into_response())
            }
            (None, _) => {
                // Other cases where we don't have a session, ask for a login
                txn.commit().await?;

                let next: PostAuthAction = next.into();
                let next: LoginRequest = next.into();
                let next = next.build_uri()?;

                Ok(Redirect::to(&next.to_string()).into_response())
            }
        }
    })
    .await;

    let response = match res {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(%err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };

    Ok((cookie_jar, response).into_response())
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ContinueAuthorizationGrant {
    data: String,
}

impl ContinueAuthorizationGrant {
    pub fn from_authorization_grant<S: StorageBackend>(grant: &AuthorizationGrant<S>) -> Self
    where
        S::AuthorizationGrantData: std::fmt::Display,
    {
        Self {
            data: grant.data.to_string(),
        }
    }

    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let qs = serde_urlencoded::to_string(self)?;
        let path_and_query = PathAndQuery::try_from(format!("/oauth2/authorize/step?{}", qs))?;
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    pub async fn fetch_authorization_grant(
        &self,
        conn: &mut PgConnection,
    ) -> anyhow::Result<AuthorizationGrant<PostgresqlBackend>> {
        let data = self.data.parse()?;
        get_grant_by_id(conn, data).await
    }
}

pub(crate) async fn step_get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(next): Query<ContinueAuthorizationGrant>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, RouteError> {
    let mut txn = pool.begin().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut txn)
        .await
        // TODO
        .context("could not load db session")?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, redirecting here after
        // logout
        let next: PostAuthAction = next.into();
        let login: LoginRequest = next.into();
        let login = login.build_uri()?;
        return Ok((cookie_jar, Redirect::to(&login.to_string())).into_response());
    };

    step(next, session, txn, &templates).await
}

async fn step(
    next: ContinueAuthorizationGrant,
    browser_session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
    templates: &Templates,
) -> Result<Response, RouteError> {
    // TODO: we should check if the grant here was started by the browser doing that
    // request using a signed cookie
    let grant = next.fetch_authorization_grant(&mut txn).await?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(anyhow::anyhow!("authorization grant not pending").into());
    }

    let reply = match browser_session.last_authentication {
        Some(Authentication { created_at, .. }) if created_at > grant.max_auth_time() => {
            let session = derive_session(&mut txn, &grant, browser_session).await?;

            let grant = fulfill_grant(&mut txn, grant, session.clone()).await?;

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
                        TokenType::AccessToken.generate(&mut rng),
                        TokenType::RefreshToken.generate(&mut rng),
                    )
                };

                let access_token =
                    add_access_token(&mut txn, &session, &access_token_str, ttl).await?;

                let _refresh_token =
                    add_refresh_token(&mut txn, &session, access_token, &refresh_token_str).await?;

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

            back_to_client(
                &grant.redirect_uri,
                grant.response_mode,
                grant.state,
                params,
                templates,
            )
            .await?
        }
        _ => {
            let next: PostAuthAction = next.into();
            let next: ReauthRequest = next.into();
            let next = next.build_uri()?;

            Redirect::to(&next.to_string()).into_response()
        }
    };

    txn.commit().await?;
    Ok(reply)
}
