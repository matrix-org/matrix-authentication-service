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
use mas_policy::{PolicyFactory, Violation};
use mas_storage::oauth2::client::insert_client;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    registration::{
        ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
    },
};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

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
            Self::Internal(_) | Self::Anyhow(_) => (
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
    State(pool): State<PgPool>,
    State(policy_factory): State<Arc<PolicyFactory>>,
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

    // Contacts was checked by the policy
    let contacts = metadata.contacts.as_deref().unwrap_or_default();

    // Grab a txn
    let mut txn = pool.begin().await?;

    // Let's generate a random client ID
    let client_id = Ulid::new();

    insert_client(
        &mut txn,
        client_id,
        metadata.redirect_uris(),
        None,
        //&metadata.response_types(),
        metadata.grant_types(),
        contacts,
        metadata
            .client_name
            .as_ref()
            .map(|l| l.non_localized().as_ref()),
        metadata.logo_uri.as_ref().map(Localized::non_localized),
        metadata.client_uri.as_ref().map(Localized::non_localized),
        metadata.policy_uri.as_ref().map(Localized::non_localized),
        metadata.tos_uri.as_ref().map(Localized::non_localized),
        metadata.jwks_uri.as_ref(),
        metadata.jwks.as_ref(),
        metadata.id_token_signed_response_alg.as_ref(),
        metadata.userinfo_signed_response_alg.as_ref(),
        metadata.token_endpoint_auth_method.as_ref(),
        metadata.token_endpoint_auth_signing_alg.as_ref(),
        metadata.initiate_login_uri.as_ref(),
    )
    .await?;

    txn.commit().await?;

    let response = ClientRegistrationResponse {
        client_id: client_id.to_string(),
        client_secret: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
    };

    Ok((StatusCode::CREATED, Json(response)))
}
