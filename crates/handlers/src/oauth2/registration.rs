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

use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_keystore::Encrypter;
use mas_policy::{PolicyFactory, Violation};
use mas_storage::{oauth2::OAuth2ClientRepository, BoxClock, BoxRng, Repository};
use mas_storage_pg::PgRepository;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    registration::{
        ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
    },
};
use rand::distributions::{Alphanumeric, DistString};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error("invalid redirect uri")]
    InvalidRedirectUri,

    #[error("invalid client metadata")]
    InvalidClientMetadata,

    #[error("denied by the policy")]
    PolicyDenied(Vec<Violation>),
}

impl_from_error_for_route!(mas_storage_pg::DatabaseError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::InstanciateError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_keystore::aead::Error);

impl From<ClientMetadataVerificationError> for RouteError {
    fn from(e: ClientMetadataVerificationError) -> Self {
        match e {
            ClientMetadataVerificationError::MissingRedirectUris
            | ClientMetadataVerificationError::RedirectUriWithFragment(_) => {
                Self::InvalidRedirectUri
            }
            _ => Self::InvalidClientMetadata,
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),
            Self::InvalidRedirectUri => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRedirectUri)),
            )
                .into_response(),
            Self::InvalidClientMetadata => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidClientMetadata)),
            )
                .into_response(),
            Self::PolicyDenied(violations) => {
                let collected = &violations
                    .iter()
                    .map(|v| v.msg.clone())
                    .collect::<Vec<String>>();
                let joined = collected.join("; ");

                (
                    StatusCode::UNAUTHORIZED,
                    Json(
                        ClientError::from(ClientErrorCode::InvalidClientMetadata)
                            .with_description(joined),
                    ),
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(pool): State<PgPool>,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(encrypter): State<Encrypter>,
    Json(body): Json<ClientMetadata>,
) -> Result<impl IntoResponse, RouteError> {
    info!(?body, "Client registration");

    // Validate the body
    let metadata = body.validate()?;

    let mut policy = policy_factory.instantiate().await?;
    let res = policy.evaluate_client_registration(&metadata).await?;
    if !res.valid() {
        return Err(RouteError::PolicyDenied(res.violations));
    }

    let mut repo = PgRepository::from_pool(&pool).await?;

    let (client_secret, encrypted_client_secret) = match metadata.token_endpoint_auth_method {
        Some(
            OAuthClientAuthenticationMethod::ClientSecretJwt
            | OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretBasic,
        ) => {
            // Let's generate a random client secret
            let client_secret = Alphanumeric.sample_string(&mut rng, 20);
            let encrypted_client_secret = encrypter.encryt_to_string(client_secret.as_bytes())?;
            (Some(client_secret), Some(encrypted_client_secret))
        }
        _ => (None, None),
    };

    let client = repo
        .oauth2_client()
        .add(
            &mut rng,
            &clock,
            metadata.redirect_uris().to_vec(),
            encrypted_client_secret,
            //&metadata.response_types(),
            metadata.grant_types().to_vec(),
            metadata.contacts.clone().unwrap_or_default(),
            metadata
                .client_name
                .clone()
                .map(Localized::to_non_localized),
            metadata.logo_uri.clone().map(Localized::to_non_localized),
            metadata.client_uri.clone().map(Localized::to_non_localized),
            metadata.policy_uri.clone().map(Localized::to_non_localized),
            metadata.tos_uri.clone().map(Localized::to_non_localized),
            metadata.jwks_uri.clone(),
            metadata.jwks.clone(),
            // XXX: those might not be right, should be function calls
            metadata.id_token_signed_response_alg.clone(),
            metadata.userinfo_signed_response_alg.clone(),
            metadata.token_endpoint_auth_method.clone(),
            metadata.token_endpoint_auth_signing_alg.clone(),
            metadata.initiate_login_uri.clone(),
        )
        .await?;

    repo.save().await?;

    let response = ClientRegistrationResponse {
        client_id: client.client_id,
        client_secret,
        // XXX: we should have a `created_at` field on the clients
        client_id_issued_at: Some(client.id.datetime().into()),
        client_secret_expires_at: None,
    };

    Ok((StatusCode::CREATED, Json(response)))
}
