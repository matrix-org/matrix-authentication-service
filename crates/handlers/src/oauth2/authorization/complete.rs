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

use anyhow::anyhow;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::SessionInfoExt;
use mas_data_model::{AuthorizationGrant, BrowserSession};
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::{PostAuthAction, Route};
use mas_storage::{
    oauth2::{
        authorization_grant::{derive_session, fulfill_grant, get_grant_by_id},
        consent::fetch_client_consent,
    },
    user::ActiveSessionLookupError,
};
use mas_templates::Templates;
use oauth2_types::requests::{AccessTokenResponse, AuthorizationResponse};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use ulid::Ulid;

use super::callback::{
    CallbackDestination, CallbackDestinationError, IntoCallbackDestinationError,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(anyhow::Error),

    #[error("authorization grant is not in a pending state")]
    NotPending,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        // TODO: better error pages
        match self {
            RouteError::NotPending => (
                StatusCode::BAD_REQUEST,
                "authorization grant not in a pending state",
            )
                .into_response(),
            RouteError::Anyhow(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            RouteError::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
        }
    }
}

impl From<anyhow::Error> for RouteError {
    fn from(e: anyhow::Error) -> Self {
        Self::Anyhow(e)
    }
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<ActiveSessionLookupError> for RouteError {
    fn from(e: ActiveSessionLookupError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<IntoCallbackDestinationError> for RouteError {
    fn from(e: IntoCallbackDestinationError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<CallbackDestinationError> for RouteError {
    fn from(e: CallbackDestinationError) -> Self {
        Self::Internal(Box::new(e))
    }
}

pub(crate) async fn get(
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let mut txn = pool.begin().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let grant = get_grant_by_id(&mut txn, grant_id).await?;

    let callback_destination = CallbackDestination::try_from(&grant)?;
    let continue_grant = PostAuthAction::continue_grant(grant_id);

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, redirecting here after
        // logout
        return Ok((cookie_jar, mas_router::Login::and_then(continue_grant).go()).into_response());
    };

    match complete(grant, session, &policy_factory, txn).await {
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
        Err(GrantCompletionError::Anyhow(e)) => Err(RouteError::Anyhow(e)),
    }
}

#[derive(Debug, Error)]
pub enum GrantCompletionError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("authorization grant is not in a pending state")]
    NotPending,

    #[error("user needs to reauthenticate")]
    RequiresReauth,

    #[error("client lacks consent")]
    RequiresConsent,

    #[error("denied by the policy")]
    PolicyViolation,
}

impl From<sqlx::Error> for GrantCompletionError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<IntoCallbackDestinationError> for GrantCompletionError {
    fn from(e: IntoCallbackDestinationError) -> Self {
        Self::Internal(Box::new(e))
    }
}

pub(crate) async fn complete(
    grant: AuthorizationGrant,
    browser_session: BrowserSession,
    policy_factory: &PolicyFactory,
    mut txn: Transaction<'_, Postgres>,
) -> Result<AuthorizationResponse<Option<AccessTokenResponse>>, GrantCompletionError> {
    let (clock, mut rng) = crate::rng_and_clock()?;

    // Verify that the grant is in a pending stage
    if !grant.stage.is_pending() {
        return Err(GrantCompletionError::NotPending);
    }

    // Check if the authentication is fresh enough
    if !browser_session.was_authenticated_after(grant.max_auth_time()) {
        txn.commit().await?;
        return Err(GrantCompletionError::RequiresReauth);
    }

    // Run through the policy
    let mut policy = policy_factory.instantiate().await?;
    let res = policy
        .evaluate_authorization_grant(&grant, &browser_session.user)
        .await?;

    if !res.valid() {
        return Err(GrantCompletionError::PolicyViolation);
    }

    let current_consent =
        fetch_client_consent(&mut txn, &browser_session.user, &grant.client).await?;

    let lacks_consent = grant
        .scope
        .difference(&current_consent)
        .any(|scope| !scope.starts_with("urn:matrix:org.matrix.msc2967.client:device:"));

    // Check if the client lacks consent *or* if consent was explicitely asked
    if lacks_consent || grant.requires_consent {
        txn.commit().await?;
        return Err(GrantCompletionError::RequiresConsent);
    }

    // All good, let's start the session
    let session = derive_session(&mut txn, &mut rng, &clock, &grant, browser_session).await?;

    let grant = fulfill_grant(&mut txn, grant, session.clone()).await?;

    // Yep! Let's complete the auth now
    let mut params = AuthorizationResponse::default();

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    // Did they request an ID token?
    if grant.response_type_id_token {
        // TODO
        return Err(anyhow!("id tokens are not implemented yet").into());
    }

    txn.commit().await?;
    Ok(params)
}
