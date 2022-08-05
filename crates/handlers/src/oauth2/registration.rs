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

use axum::{response::IntoResponse, Extension, Json};
use hyper::StatusCode;
use mas_iana::oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod};
use mas_policy::{PolicyFactory, Violation};
use mas_storage::oauth2::client::insert_client;
use oauth2_types::{
    errors::{INVALID_CLIENT_METADATA, INVALID_REDIRECT_URI, SERVER_ERROR},
    registration::{ClientMetadata, ClientRegistrationResponse},
    requests::GrantType,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("invalid redirect uri")]
    InvalidRedirectUri,

    #[error("invalid client metadata")]
    InvalidClientMetadata,

    #[error("denied by the policy")]
    PolicyDenied(Vec<Violation>),
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

// TODO: there is probably a better way to do achieve this. ClientError only
// works for static strings
#[derive(serde::Serialize)]
struct PolicyError {
    error: String,
    error_description: String,
}

impl PolicyError {
    #[must_use]
    pub const fn new(error: String, error_description: String) -> Self {
        Self {
            error,
            error_description,
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) | Self::Anyhow(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(SERVER_ERROR)).into_response()
            }
            Self::InvalidRedirectUri => {
                (StatusCode::BAD_REQUEST, Json(INVALID_REDIRECT_URI)).into_response()
            }
            Self::InvalidClientMetadata => {
                (StatusCode::BAD_REQUEST, Json(INVALID_CLIENT_METADATA)).into_response()
            }
            Self::PolicyDenied(violations) => {
                let collected = &violations
                    .iter()
                    .map(|v| v.msg.clone())
                    .collect::<Vec<String>>();
                let joined = collected.join("; ");

                (
                    StatusCode::UNAUTHORIZED,
                    Json(PolicyError::new(
                        "invalid_client_metadata".to_owned(),
                        joined,
                    )),
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Extension(policy_factory): Extension<Arc<PolicyFactory>>,
    Json(body): Json<ClientMetadata>,
) -> Result<impl IntoResponse, RouteError> {
    info!(?body, "Client registration");

    // Let's validate a bunch of things on the client body first
    for uri in &body.redirect_uris {
        if uri.fragment().is_some() {
            return Err(RouteError::InvalidRedirectUri);
        }
    }

    // Check that the client did not send both a jwks and a jwks_uri
    if body.jwks_uri.is_some() && body.jwks.is_some() {
        return Err(RouteError::InvalidClientMetadata);
    }

    // Check that the grant_types and the response_types are coherent
    let has_implicit = body.grant_types.contains(&GrantType::Implicit);
    let has_authorization_code = body.grant_types.contains(&GrantType::AuthorizationCode);
    let has_both = has_implicit && has_authorization_code;

    for response_type in &body.response_types {
        let is_ok = match response_type {
            OAuthAuthorizationEndpointResponseType::Code => has_authorization_code,
            OAuthAuthorizationEndpointResponseType::CodeIdToken
            | OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
            | OAuthAuthorizationEndpointResponseType::CodeToken => has_both,
            OAuthAuthorizationEndpointResponseType::IdToken
            | OAuthAuthorizationEndpointResponseType::IdTokenToken
            | OAuthAuthorizationEndpointResponseType::Token => has_implicit,
            OAuthAuthorizationEndpointResponseType::None => true,
        };

        if !is_ok {
            return Err(RouteError::InvalidClientMetadata);
        }
    }

    // If the private_key_jwt auth method is used, check that we actually have a
    // JWKS for that client
    if body.token_endpoint_auth_method == Some(OAuthClientAuthenticationMethod::PrivateKeyJwt)
        && body.jwks_uri.is_none()
        && body.jwks.is_none()
    {
        return Err(RouteError::InvalidClientMetadata);
    }

    let mut policy = policy_factory.instantiate().await?;
    let res = policy.evaluate_client_registration(&body).await?;
    if !res.valid() {
        return Err(RouteError::PolicyDenied(res.violations));
    }

    // Grab a txn
    let mut txn = pool.begin().await?;

    // Let's generate a random client ID
    let client_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    insert_client(
        &mut txn,
        &client_id,
        &body.redirect_uris,
        None,
        &body.response_types,
        &body.grant_types,
        &body.contacts,
        body.client_name.as_deref(),
        body.logo_uri.as_ref(),
        body.client_uri.as_ref(),
        body.policy_uri.as_ref(),
        body.tos_uri.as_ref(),
        body.jwks_uri.as_ref(),
        body.jwks.as_ref(),
        body.id_token_signed_response_alg,
        body.userinfo_signed_response_alg,
        body.token_endpoint_auth_method,
        body.token_endpoint_auth_signing_alg,
        body.initiate_login_uri.as_ref(),
    )
    .await?;

    txn.commit().await?;

    let response = ClientRegistrationResponse {
        client_id,
        client_secret: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
    };

    Ok((StatusCode::CREATED, Json(response)))
}
