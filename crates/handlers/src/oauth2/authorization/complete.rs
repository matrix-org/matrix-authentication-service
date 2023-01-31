// Copyright 2022 The Matrix.org Foundation C.I.C.
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
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::SessionInfoExt;
use mas_data_model::{AuthorizationGrant, BrowserSession, Client};
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::{PostAuthAction, Route};
use mas_storage::{
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository, OAuth2SessionRepository},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::Templates;
use oauth2_types::requests::{AccessTokenResponse, AuthorizationResponse};
use thiserror::Error;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("authorization grant was not found")]
    NotFound,

    #[error("authorization grant is not in a pending state")]
    NotPending,

    #[error("failed to load client")]
    NoSuchClient,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        // TODO: better error pages
        match self {
            RouteError::NotFound => {
                (StatusCode::NOT_FOUND, "authorization grant was not found").into_response()
            }
            RouteError::NotPending => (
                StatusCode::BAD_REQUEST,
                "authorization grant not in a pending state",
            )
                .into_response(),
            RouteError::Internal(_) | Self::NoSuchClient => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::InstanciateError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

#[tracing::instrument(
    name = "handlers.oauth2.authorization_complete.get",
    fields(grant.id = %grant_id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    rng: BoxRng,
    clock: BoxClock,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let callback_destination = CallbackDestination::try_from(&grant)?;
    let continue_grant = PostAuthAction::continue_grant(grant.id);

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, redirecting here after
        // logout
        return Ok((cookie_jar, mas_router::Login::and_then(continue_grant).go()).into_response());
    };

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient)?;

    match complete(rng, clock, grant, client, session, &policy_factory, repo).await {
        Ok(params) => {
            let res = callback_destination.go(&templates, params).await?;
            Ok((cookie_jar, res).into_response())
        }
        Err(GrantCompletionError::RequiresReauth) => Ok((
            cookie_jar,
            mas_router::Reauth::and_then(continue_grant).go(),
        )
            .into_response()),
        Err(GrantCompletionError::RequiresConsent | GrantCompletionError::PolicyViolation) => {
            let next = mas_router::Consent(grant_id);
            Ok((cookie_jar, next.go()).into_response())
        }
        Err(GrantCompletionError::NotPending) => Err(RouteError::NotPending),
        Err(GrantCompletionError::Internal(e)) => Err(RouteError::Internal(e)),
    }
}

#[derive(Debug, Error)]
pub enum GrantCompletionError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("authorization grant is not in a pending state")]
    NotPending,

    #[error("user needs to reauthenticate")]
    RequiresReauth,

    #[error("client lacks consent")]
    RequiresConsent,

    #[error("denied by the policy")]
    PolicyViolation,
}

impl_from_error_for_route!(GrantCompletionError: mas_storage::RepositoryError);
impl_from_error_for_route!(GrantCompletionError: super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(GrantCompletionError: mas_policy::LoadError);
impl_from_error_for_route!(GrantCompletionError: mas_policy::InstanciateError);
impl_from_error_for_route!(GrantCompletionError: mas_policy::EvaluationError);

pub(crate) async fn complete(
    mut rng: BoxRng,
    clock: BoxClock,
    grant: AuthorizationGrant,
    client: Client,
    browser_session: BrowserSession,
    policy_factory: &PolicyFactory,
    mut repo: BoxRepository,
) -> Result<AuthorizationResponse<Option<AccessTokenResponse>>, GrantCompletionError> {
    // Verify that the grant is in a pending stage
    if !grant.stage.is_pending() {
        return Err(GrantCompletionError::NotPending);
    }

    // Check if the authentication is fresh enough
    if !browser_session.was_authenticated_after(grant.max_auth_time()) {
        repo.save().await?;
        return Err(GrantCompletionError::RequiresReauth);
    }

    // Run through the policy
    let mut policy = policy_factory.instantiate().await?;
    let res = policy
        .evaluate_authorization_grant(&grant, &client, &browser_session.user)
        .await?;

    if !res.valid() {
        return Err(GrantCompletionError::PolicyViolation);
    }

    let current_consent = repo
        .oauth2_client()
        .get_consent_for_user(&client, &browser_session.user)
        .await?;

    let lacks_consent = grant
        .scope
        .difference(&current_consent)
        .any(|scope| !scope.starts_with("urn:matrix:org.matrix.msc2967.client:device:"));

    // Check if the client lacks consent *or* if consent was explicitely asked
    if lacks_consent || grant.requires_consent {
        repo.save().await?;
        return Err(GrantCompletionError::RequiresConsent);
    }

    // All good, let's start the session
    let session = repo
        .oauth2_session()
        .create_from_grant(&mut rng, &clock, &grant, &browser_session)
        .await?;

    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&clock, &session, grant)
        .await?;

    // Yep! Let's complete the auth now
    let mut params = AuthorizationResponse::default();

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    // Did they request an ID token?
    if grant.response_type_id_token {
        // TODO
        return Err(GrantCompletionError::Internal(
            "ID tokens are not implemented yet".into(),
        ));
    }

    repo.save().await?;
    Ok(params)
}
