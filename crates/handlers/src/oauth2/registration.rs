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

use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_axum_utils::sentry::SentryEventID;
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_keystore::Encrypter;
use mas_policy::{Policy, Violation};
use mas_storage::{oauth2::OAuth2ClientRepository, BoxClock, BoxRepository, BoxRng};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    registration::{
        ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
    },
};
use psl::Psl;
use rand::distributions::{Alphanumeric, DistString};
use thiserror::Error;
use tracing::info;
use url::Url;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    JsonExtract(#[from] axum::extract::rejection::JsonRejection),

    #[error("invalid client metadata")]
    InvalidClientMetadata(#[from] ClientMetadataVerificationError),

    #[error("{0} is a public suffix, not a valid domain")]
    UrlIsPublicSuffix(&'static str),

    #[error("denied by the policy: {0:?}")]
    PolicyDenied(Vec<Violation>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_keystore::aead::Error);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
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

            // This error happens if the any of the client's URIs are public suffixes. We return
            // an `invalid_redirect_uri` error if it's a `redirect_uri`, else we return an
            // `invalid_client_metadata` error.
            Self::UrlIsPublicSuffix("redirect_uri") => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRedirectUri)
                        .with_description("redirect_uri is not using a valid domain".to_owned()),
                ),
            )
                .into_response(),

            Self::UrlIsPublicSuffix(field) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(format!("{field} is not using a valid domain")),
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
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

/// Check if the host of the given URL is a public suffix
fn host_is_public_suffix(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().as_bytes();
    let Some(suffix) = psl::List.suffix(host) else {
        // There is no suffix, which is the case for empty hosts, like with custom
        // schemes
        return false;
    };

    if !suffix.is_known() {
        // The suffix is not known, so it's not a public suffix
        return false;
    }

    // We want to cover two cases:
    // - The host is the suffix itself, like `com`
    // - The host is a dot followed by the suffix, like `.com`
    if host.len() <= suffix.as_bytes().len() + 1 {
        // The host only has the suffix in it, so it's a public suffix
        return true;
    }

    false
}

/// Check if any of the URLs in the given `Localized` field is a public suffix
fn localised_url_has_public_suffix(url: &Localized<Url>) -> bool {
    url.iter().any(|(_lang, url)| host_is_public_suffix(url))
}

#[tracing::instrument(name = "handlers.oauth2.registration.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    mut policy: Policy,
    State(encrypter): State<Encrypter>,
    body: Result<Json<ClientMetadata>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    // Propagate any JSON extraction error
    let Json(body) = body?;

    info!(?body, "Client registration");

    // Validate the body
    let metadata = body.validate()?;

    // Some extra validation that is hard to do in OPA and not done by the
    // `validate` method either
    if let Some(client_uri) = &metadata.client_uri {
        if localised_url_has_public_suffix(client_uri) {
            return Err(RouteError::UrlIsPublicSuffix("client_uri"));
        }
    }

    if let Some(logo_uri) = &metadata.logo_uri {
        if localised_url_has_public_suffix(logo_uri) {
            return Err(RouteError::UrlIsPublicSuffix("logo_uri"));
        }
    }

    if let Some(policy_uri) = &metadata.policy_uri {
        if localised_url_has_public_suffix(policy_uri) {
            return Err(RouteError::UrlIsPublicSuffix("policy_uri"));
        }
    }

    if let Some(tos_uri) = &metadata.tos_uri {
        if localised_url_has_public_suffix(tos_uri) {
            return Err(RouteError::UrlIsPublicSuffix("tos_uri"));
        }
    }

    if let Some(initiate_login_uri) = &metadata.initiate_login_uri {
        if host_is_public_suffix(initiate_login_uri) {
            return Err(RouteError::UrlIsPublicSuffix("initiate_login_uri"));
        }
    }

    for redirect_uri in metadata.redirect_uris() {
        if host_is_public_suffix(redirect_uri) {
            return Err(RouteError::UrlIsPublicSuffix("redirect_uri"));
        }
    }

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
            metadata.application_type.clone(),
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
    use url::Url;

    use crate::{
        oauth2::registration::host_is_public_suffix,
        test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState},
    };

    #[test]
    fn test_public_suffix_list() {
        fn url_is_public_suffix(url: &str) -> bool {
            host_is_public_suffix(&Url::parse(url).unwrap())
        }

        assert!(url_is_public_suffix("https://.com"));
        assert!(url_is_public_suffix("https://.com."));
        assert!(url_is_public_suffix("https://co.uk"));
        assert!(url_is_public_suffix("https://github.io"));
        assert!(!url_is_public_suffix("https://example.com"));
        assert!(!url_is_public_suffix("https://example.com."));
        assert!(!url_is_public_suffix("https://x.com"));
        assert!(!url_is_public_suffix("https://x.com."));
        assert!(!url_is_public_suffix("https://matrix-org.github.io"));
        assert!(!url_is_public_suffix("http://localhost"));
        assert!(!url_is_public_suffix("org.matrix:/callback"));
        assert!(!url_is_public_suffix("http://somerandominternaldomain"));
    }

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

        // Using a public suffix
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "contacts": ["hello@example.com"],
                "client_uri": "https://github.io/",
                "redirect_uris": ["https://github.io/"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidClientMetadata);
        assert_eq!(
            response.error_description.unwrap(),
            "client_uri is not using a valid domain"
        );

        // Using a public suffix in a translated URL
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "contacts": ["hello@example.com"],
                "client_uri": "https://example.com/",
                "client_uri#fr-FR": "https://github.io/",
                "redirect_uris": ["https://example.com/"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::InvalidClientMetadata);
        assert_eq!(
            response.error_description.unwrap(),
            "client_uri is not using a valid domain"
        );
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
