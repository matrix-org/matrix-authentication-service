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

use std::sync::Arc;

use anyhow::{anyhow, Context};
use axum::{
    extract::{Extension, Form},
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::SessionInfoExt;
use mas_config::Encrypter;
use mas_data_model::{AuthorizationCode, Device, Pkce};
use mas_iana::oauth::OAuthAuthorizationEndpointResponseType;
use mas_policy::PolicyFactory;
use mas_router::{PostAuthAction, Route};
use mas_storage::oauth2::{
    authorization_grant::new_authorization_grant,
    client::{lookup_client_by_client_id, ClientFetchError},
};
use mas_templates::Templates;
use oauth2_types::{
    errors::{
        ACCESS_DENIED, CONSENT_REQUIRED, INTERACTION_REQUIRED, INVALID_REQUEST, LOGIN_REQUIRED,
        REGISTRATION_NOT_SUPPORTED, REQUEST_NOT_SUPPORTED, REQUEST_URI_NOT_SUPPORTED, SERVER_ERROR,
        UNAUTHORIZED_CLIENT,
    },
    pkce,
    prelude::*,
    requests::{AuthorizationRequest, GrantType, Prompt, ResponseMode},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;

use self::{callback::CallbackDestination, complete::GrantCompletionError};

mod callback;
pub mod complete;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(anyhow::Error),

    #[error("could not find client")]
    ClientNotFound,

    #[error("invalid redirect uri")]
    InvalidRedirectUri(#[from] self::callback::InvalidRedirectUriError),

    #[error("invalid redirect uri")]
    UnknownRedirectUri(#[from] mas_data_model::InvalidRedirectUriError),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        // TODO: better error pages
        match self {
            RouteError::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            RouteError::Anyhow(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            RouteError::ClientNotFound => {
                (StatusCode::BAD_REQUEST, "could not find client").into_response()
            }
            RouteError::InvalidRedirectUri(e) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect URI ({})", e),
            )
                .into_response(),
            RouteError::UnknownRedirectUri(e) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect URI ({})", e),
            )
                .into_response(),
        }
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<self::callback::CallbackDestinationError> for RouteError {
    fn from(e: self::callback::CallbackDestinationError) -> Self {
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
            Some(M::Query) => Err(anyhow!("invalid response mode")),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn get(
    Extension(policy_factory): Extension<Arc<PolicyFactory>>,
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(params): Form<Params>,
) -> Result<Response, RouteError> {
    let mut txn = pool.begin().await?;

    // First, figure out what client it is
    let client = lookup_client_by_client_id(&mut txn, &params.auth.client_id).await?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(response_type, params.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        response_mode,
        redirect_uri.clone(),
        params.auth.state.clone(),
    )?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();

    // One day, we will have try blocks
    let res: Result<Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        async move {
            let maybe_session = session_info
                .load_session(&mut txn)
                .await
                .context("failed to load browser session")?;

            // Check if the request/request_uri/registration params are used. If so, reply
            // with the right error since we don't support them.
            if params.auth.request.is_some() {
                return Ok(callback_destination
                    .go(&templates, REQUEST_NOT_SUPPORTED)
                    .await?);
            }

            if params.auth.request_uri.is_some() {
                return Ok(callback_destination
                    .go(&templates, REQUEST_URI_NOT_SUPPORTED)
                    .await?);
            }

            if params.auth.registration.is_some() {
                return Ok(callback_destination
                    .go(&templates, REGISTRATION_NOT_SUPPORTED)
                    .await?);
            }

            // Check if it is allowed to use this grant type
            if !client.grant_types.contains(&GrantType::AuthorizationCode) {
                return Ok(callback_destination
                    .go(&templates, UNAUTHORIZED_CLIENT)
                    .await?);
            }

            // Fail early if prompt=none and there is no active session
            if params.auth.prompt == Some(Prompt::None) && maybe_session.is_none() {
                return Ok(callback_destination.go(&templates, LOGIN_REQUIRED).await?);
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
                    return Ok(callback_destination.go(&templates, INVALID_REQUEST).await?);
                }

                None
            };

            // Generate the device ID
            let device = Device::generate(&mut thread_rng());
            let device_scope = device.to_scope_token();

            let scope = {
                let mut s = params.auth.scope.clone();
                s.insert(device_scope);
                s
            };

            let requires_consent = params.auth.prompt == Some(Prompt::Consent);

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
                requires_consent,
            )
            .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.data);

            let res = match (maybe_session, params.auth.prompt) {
                // Cases where there is no active session, redirect to the relevant page
                (None, Some(Prompt::None)) => {
                    // This case should already be handled earlier
                    unreachable!();
                }
                (None, Some(Prompt::Create)) => {
                    // Client asked for a registration, show the registration prompt
                    txn.commit().await?;

                    mas_router::Register::and_then(continue_grant)
                        .go()
                        .into_response()
                }
                (None, _) => {
                    // Other cases where we don't have a session, ask for a login
                    txn.commit().await?;

                    mas_router::Login::and_then(continue_grant)
                        .go()
                        .into_response()
                }

                // Special case when we already have a sesion but prompt=login|select_account
                (Some(_), Some(Prompt::Login | Prompt::SelectAccount)) => {
                    // TODO: better pages here
                    txn.commit().await?;

                    mas_router::Reauth::and_then(continue_grant)
                        .go()
                        .into_response()
                }

                // Else, we immediately try to complete the authorization grant
                (Some(user_session), Some(Prompt::None)) => {
                    // With prompt=none, we should get back to the client immediately
                    match self::complete::complete(grant, user_session, &policy_factory, txn).await
                    {
                        Ok(params) => callback_destination.go(&templates, params).await?,
                        Err(GrantCompletionError::RequiresConsent) => {
                            callback_destination
                                .go(&templates, CONSENT_REQUIRED)
                                .await?
                        }
                        Err(GrantCompletionError::RequiresReauth) => {
                            callback_destination
                                .go(&templates, INTERACTION_REQUIRED)
                                .await?
                        }
                        Err(GrantCompletionError::PolicyViolation) => {
                            callback_destination.go(&templates, ACCESS_DENIED).await?
                        }
                        Err(GrantCompletionError::Anyhow(a)) => return Err(RouteError::Anyhow(a)),
                        Err(GrantCompletionError::Internal(e)) => {
                            return Err(RouteError::Internal(e))
                        }
                        Err(GrantCompletionError::NotPending) => {
                            // This should never happen
                            return Err(anyhow!("authorization grant is not pending").into());
                        }
                    }
                }
                (Some(user_session), _) => {
                    let grant_id = grant.data;
                    // Else, we show the relevant reauth/consent page if necessary
                    match self::complete::complete(grant, user_session, &policy_factory, txn).await
                    {
                        Ok(params) => callback_destination.go(&templates, params).await?,
                        Err(GrantCompletionError::RequiresConsent) => {
                            mas_router::Consent(grant_id).go().into_response()
                        }
                        Err(GrantCompletionError::RequiresReauth) => {
                            mas_router::Reauth::and_then(continue_grant)
                                .go()
                                .into_response()
                        }
                        Err(GrantCompletionError::PolicyViolation) => {
                            callback_destination.go(&templates, ACCESS_DENIED).await?
                        }
                        Err(GrantCompletionError::Anyhow(a)) => return Err(RouteError::Anyhow(a)),
                        Err(GrantCompletionError::Internal(e)) => {
                            return Err(RouteError::Internal(e))
                        }
                        Err(GrantCompletionError::NotPending) => {
                            // This should never happen
                            return Err(anyhow!("authorization grant is not pending").into());
                        }
                    }
                }
            };

            Ok(res)
        }
    })
    .await;

    let response = match res {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(%err);
            callback_destination.go(&templates, SERVER_ERROR).await?
        }
    };

    Ok((cookie_jar, response).into_response())
}
