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
use mas_storage::{oauth2::OAuth2ClientRepository, BoxClock, BoxRepository, BoxRng};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    registration::{
        ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
    },
};
use rand::distributions::{Alphanumeric, DistString};
use thiserror::Error;
use tracing::info;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    JsonExtract(#[from] axum::extract::rejection::JsonRejection),

    #[error("invalid client metadata")]
    InvalidClientMetadata(#[from] ClientMetadataVerificationError),

    #[error("denied by the policy: {0:?}")]
    PolicyDenied(Vec<Violation>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::InstanciateError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_keystore::aead::Error);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),

            // This error happens if we managed to parse the incomiong JSON but it can't be
            // deserialized to the expected type. In this case we return an
            // `invalid_client_metadata` error with the details of the error.
            Self::JsonExtract(axum::extract::rejection::JsonRejection::JsonDataError(e)) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),

            // For all other JSON errors we return a `invalid_request` error, since this is
            // probably due to a malformed request.
            Self::JsonExtract(_) => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),

            // This error comes from the `ClientMetadata::validate` method. We return an
            // `invalid_redirect_uri` error if the error is related to the redirect URIs, else we
            // return an `invalid_client_metadata` error.
            Self::InvalidClientMetadata(
                ClientMetadataVerificationError::MissingRedirectUris
                | ClientMetadataVerificationError::RedirectUriWithFragment(_),
            ) => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRedirectUri)),
            )
                .into_response(),

            Self::InvalidClientMetadata(e) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),

            // For policy violations, we return an `invalid_client_metadata` error with the details
            // of the violations in most cases. If a violation includes `redirect_uri` in the
            // message, we return an `invalid_redirect_uri` error instead.
            Self::PolicyDenied(violations) => {
                // TODO: detect them better
                let code = if violations.iter().any(|v| v.msg.contains("redirect_uri")) {
                    ClientErrorCode::InvalidRedirectUri
                } else {
                    ClientErrorCode::InvalidClientMetadata
                };

                let collected = &violations
                    .iter()
                    .map(|v| v.msg.clone())
                    .collect::<Vec<String>>();
                let joined = collected.join("; ");

                (
                    StatusCode::BAD_REQUEST,
                    Json(ClientError::from(code).with_description(joined)),
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(name = "handlers.oauth2.registration.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(encrypter): State<Encrypter>,
    body: Result<Json<ClientMetadata>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    // Propagate any JSON extraction error
    let Json(body) = body?;

    info!(?body, "Client registration");

    // Validate the body
    let metadata = body.validate()?;

    let mut policy = policy_factory.instantiate().await?;
    let res = policy.evaluate_client_registration(&metadata).await?;
    if !res.valid() {
        return Err(RouteError::PolicyDenied(res.violations));
    }

    let (client_secret, encrypted_client_secret) = match metadata.token_endpoint_auth_method {
        Some(
            OAuthClientAuthenticationMethod::ClientSecretJwt
            | OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretBasic,
        ) => {
            // Let's generate a random client secret
            let client_secret = Alphanumeric.sample_string(&mut rng, 20);
            let encrypted_client_secret = encrypter.encrypt_to_string(client_secret.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        errors::{ClientError, ClientErrorCode},
        registration::ClientRegistrationResponse,
    };
    use sqlx::PgPool;

    use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_registration_error(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Body is not a JSON
        let request = Request::post(mas_router::OAuth2RegistrationEndpoint::PATH)
            .body("this is not a json".to_owned())
            .unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidRequest);

        // Invalid client metadata
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "this is not a uri",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidClientMetadata);

        // Invalid redirect URI
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "application_type": "web",
                "contacts": ["hello@example.com"],
                "client_uri": "https://example.com/",
                "redirect_uris": ["http://this-is-insecure.com/"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidRedirectUri);

        // Incoherent response types
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "contacts": ["hello@example.com"],
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/"],
                "response_types": ["id_token"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidClientMetadata);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_registration(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // A successful registration with no authentication should not return a client
        // secret
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "contacts": ["hello@example.com"],
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: ClientRegistrationResponse = response.json();
        assert!(response.client_secret.is_none());

        // A successful registration with client_secret based authentication should
        // return a client secret
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "contacts": ["hello@example.com"],
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: ClientRegistrationResponse = response.json();
        assert!(response.client_secret.is_some());
    }
}
