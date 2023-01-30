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

use axum::{
    extract::{Form, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::SessionInfoExt;
use mas_data_model::{AuthorizationCode, Pkce};
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::{PostAuthAction, Route};
use mas_storage::{
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::Templates;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce,
    requests::{AuthorizationRequest, GrantType, Prompt, ResponseMode},
    response_type::ResponseType,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use thiserror::Error;

use self::{callback::CallbackDestination, complete::GrantCompletionError};
use crate::impl_from_error_for_route;

mod callback;
pub mod complete;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("could not find client")]
    ClientNotFound,

    #[error("invalid response mode")]
    InvalidResponseMode,

    #[error("invalid parameters")]
    IntoCallbackDestination(#[from] self::callback::IntoCallbackDestinationError),

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
            RouteError::ClientNotFound => {
                (StatusCode::BAD_REQUEST, "could not find client").into_response()
            }
            RouteError::InvalidResponseMode => {
                (StatusCode::BAD_REQUEST, "invalid response mode").into_response()
            }
            RouteError::IntoCallbackDestination(e) => {
                (StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
            RouteError::UnknownRedirectUri(e) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect URI ({e})"),
            )
                .into_response(),
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(self::callback::CallbackDestinationError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::InstanciateError);
impl_from_error_for_route!(mas_policy::EvaluationError);

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
    response_type: &ResponseType,
    suggested_response_mode: Option<ResponseMode>,
) -> Result<ResponseMode, RouteError> {
    use ResponseMode as M;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.has_token() || response_type.has_id_token() {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(RouteError::InvalidResponseMode),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.get",
    fields(client.id = %params.auth.client_id),
    skip_all,
    err,
)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(params): Form<Params>,
) -> Result<Response, RouteError> {
    // First, figure out what client it is
    let client = repo
        .oauth2_client()
        .find_by_client_id(&params.auth.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(&response_type, params.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        &response_mode,
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
            let maybe_session = session_info.load_session(&mut repo).await?;
            let prompt = params.auth.prompt.as_deref().unwrap_or_default();

            // Check if the request/request_uri/registration params are used. If so, reply
            // with the right error since we don't support them.
            if params.auth.request.is_some() {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::RequestNotSupported),
                    )
                    .await?);
            }

            if params.auth.request_uri.is_some() {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::RequestUriNotSupported),
                    )
                    .await?);
            }

            // Check if the client asked for a `token` response type, and bail out if it's
            // the case, since we don't support them
            if response_type.has_token() {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::UnsupportedResponseType),
                    )
                    .await?);
            }

            // If the client asked for a `id_token` response type, we must check if it can
            // use the `implicit` grant type
            if response_type.has_id_token() && !client.grant_types.contains(&GrantType::Implicit) {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::UnauthorizedClient),
                    )
                    .await?);
            }

            if params.auth.registration.is_some() {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::RegistrationNotSupported),
                    )
                    .await?);
            }

            // Fail early if prompt=none and there is no active session
            if prompt.contains(&Prompt::None) && maybe_session.is_none() {
                return Ok(callback_destination
                    .go(
                        &templates,
                        ClientError::from(ClientErrorCode::LoginRequired),
                    )
                    .await?);
            }

            let code: Option<AuthorizationCode> = if response_type.has_code() {
                // Check if it is allowed to use this grant type
                if !client.grant_types.contains(&GrantType::AuthorizationCode) {
                    return Ok(callback_destination
                        .go(
                            &templates,
                            ClientError::from(ClientErrorCode::UnauthorizedClient),
                        )
                        .await?);
                }

                // 32 random alphanumeric characters, about 190bit of entropy
                let code: String = (&mut rng)
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
                    return Ok(callback_destination
                        .go(
                            &templates,
                            ClientError::from(ClientErrorCode::InvalidRequest),
                        )
                        .await?);
                }

                None
            };

            let requires_consent = prompt.contains(&Prompt::Consent);

            let grant = repo
                .oauth2_authorization_grant()
                .add(
                    &mut rng,
                    &clock,
                    &client,
                    redirect_uri.clone(),
                    params.auth.scope,
                    code,
                    params.auth.state.clone(),
                    params.auth.nonce,
                    params.auth.max_age,
                    response_mode,
                    response_type.has_id_token(),
                    requires_consent,
                )
                .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let res = match maybe_session {
                // Cases where there is no active session, redirect to the relevant page
                None if prompt.contains(&Prompt::None) => {
                    // This case should already be handled earlier
                    unreachable!();
                }
                None if prompt.contains(&Prompt::Create) => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    mas_router::Register::and_then(continue_grant)
                        .go()
                        .into_response()
                }
                None => {
                    // Other cases where we don't have a session, ask for a login
                    repo.save().await?;

                    mas_router::Login::and_then(continue_grant)
                        .go()
                        .into_response()
                }

                // Special case when we already have a sesion but prompt=login|select_account
                Some(_)
                    if prompt.contains(&Prompt::Login)
                        || prompt.contains(&Prompt::SelectAccount) =>
                {
                    // TODO: better pages here
                    repo.save().await?;

                    mas_router::Reauth::and_then(continue_grant)
                        .go()
                        .into_response()
                }

                // Else, we immediately try to complete the authorization grant
                Some(user_session) if prompt.contains(&Prompt::None) => {
                    // With prompt=none, we should get back to the client immediately
                    match self::complete::complete(
                        rng,
                        clock,
                        grant,
                        user_session,
                        &policy_factory,
                        repo,
                    )
                    .await
                    {
                        Ok(params) => callback_destination.go(&templates, params).await?,
                        Err(GrantCompletionError::RequiresConsent) => {
                            callback_destination
                                .go(
                                    &templates,
                                    ClientError::from(ClientErrorCode::ConsentRequired),
                                )
                                .await?
                        }
                        Err(GrantCompletionError::RequiresReauth) => {
                            callback_destination
                                .go(
                                    &templates,
                                    ClientError::from(ClientErrorCode::InteractionRequired),
                                )
                                .await?
                        }
                        Err(GrantCompletionError::PolicyViolation) => {
                            callback_destination
                                .go(&templates, ClientError::from(ClientErrorCode::AccessDenied))
                                .await?
                        }
                        Err(GrantCompletionError::Internal(e)) => {
                            return Err(RouteError::Internal(e))
                        }
                        Err(
                            e @ (GrantCompletionError::NotPending
                            | GrantCompletionError::NoSuchClient),
                        ) => {
                            // This should never happen
                            return Err(RouteError::Internal(Box::new(e)));
                        }
                    }
                }
                Some(user_session) => {
                    let grant_id = grant.id;
                    // Else, we show the relevant reauth/consent page if necessary
                    match self::complete::complete(
                        rng,
                        clock,
                        grant,
                        user_session,
                        &policy_factory,
                        repo,
                    )
                    .await
                    {
                        Ok(params) => callback_destination.go(&templates, params).await?,
                        Err(
                            GrantCompletionError::RequiresConsent
                            | GrantCompletionError::PolicyViolation,
                        ) => {
                            // We're redirecting to the consent URI in both 'consent required' and
                            // 'policy violation' cases, because we reevaluate the policy on this
                            // page, and show the error accordingly
                            // XXX: is this the right approach?
                            mas_router::Consent(grant_id).go().into_response()
                        }
                        Err(GrantCompletionError::RequiresReauth) => {
                            mas_router::Reauth::and_then(continue_grant)
                                .go()
                                .into_response()
                        }
                        Err(GrantCompletionError::Internal(e)) => {
                            return Err(RouteError::Internal(e))
                        }
                        Err(
                            e @ (GrantCompletionError::NotPending
                            | GrantCompletionError::NoSuchClient),
                        ) => {
                            // This should never happen
                            return Err(RouteError::Internal(Box::new(e)));
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
            callback_destination
                .go(&templates, ClientError::from(ClientErrorCode::ServerError))
                .await?
        }
    };

    Ok((cookie_jar, response).into_response())
}
