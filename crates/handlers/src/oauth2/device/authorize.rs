// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use axum::{extract::State, response::IntoResponse, Json, TypedHeader};
use chrono::Duration;
use headers::{CacheControl, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
    sentry::SentryEventID,
};
use mas_data_model::UserAgent;
use mas_keystore::Encrypter;
use mas_router::UrlBuilder;
use mas_storage::{oauth2::OAuth2DeviceCodeGrantParams, BoxClock, BoxRepository, BoxRng};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{DeviceAuthorizationRequest, DeviceAuthorizationResponse, GrantType},
    scope::ScopeToken,
};
use rand::distributions::{Alphanumeric, DistString};
use thiserror::Error;

use crate::{impl_from_error_for_route, BoundActivityTracker};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("could not verify client credentials")]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);

        let response = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            ),
            Self::ClientNotFound | Self::ClientCredentialsVerification(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            ),
            Self::ClientNotAllowed => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.device.request.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
    err,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    State(http_client_factory): State<HttpClientFactory>,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<DeviceAuthorizationRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // Reuse the token endpoint auth method to verify the client
    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::ClientNotAllowed);
    }

    let scope = client_authorization
        .form
        .and_then(|f| f.scope)
        // XXX: Is this really how we do empty scopes?
        .unwrap_or(std::iter::empty::<ScopeToken>().collect());

    let expires_in = Duration::minutes(20);

    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    let ip_address = activity_tracker.ip();

    let device_code = Alphanumeric.sample_string(&mut rng, 32);
    let user_code = Alphanumeric.sample_string(&mut rng, 6).to_uppercase();

    let device_code = repo
        .oauth2_device_code_grant()
        .add(
            &mut rng,
            &clock,
            OAuth2DeviceCodeGrantParams {
                client: &client,
                scope,
                device_code,
                user_code,
                expires_in,
                user_agent,
                ip_address,
            },
        )
        .await?;

    repo.save().await?;

    let response = DeviceAuthorizationResponse {
        device_code: device_code.device_code,
        user_code: device_code.user_code.clone(),
        verification_uri: url_builder.device_code_link(),
        verification_uri_complete: Some(url_builder.device_code_link_full(device_code.user_code)),
        expires_in,
        interval: Some(Duration::seconds(5)),
    };

    Ok((
        StatusCode::OK,
        TypedHeader(CacheControl::new().with_no_store()),
        TypedHeader(Pragma::no_cache()),
        Json(response),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse, requests::DeviceAuthorizationResponse,
    };
    use sqlx::PgPool;

    use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_device_code_request(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;

        // Test the happy path: the client is allowed to use the device code grant type
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: DeviceAuthorizationResponse = response.json();
        assert_eq!(response.device_code.len(), 32);
        assert_eq!(response.user_code.len(), 6);
    }
}
