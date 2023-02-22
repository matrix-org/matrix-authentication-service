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

use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
};
use mas_data_model::TokenType;
use mas_iana::oauth::OAuthTokenTypeHint;
use mas_keystore::Encrypter;
use mas_storage::{BoxClock, BoxRepository};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::RevocationRequest,
};
use thiserror::Error;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("could not verify client credentials")]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("client is unauthorized")]
    UnauthorizedClient,

    #[error("unsupported token type")]
    UnsupportedTokenType,

    #[error("unknown token")]
    UnknownToken,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),

            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),

            Self::ClientNotFound | Self::ClientCredentialsVerification(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),

            Self::ClientNotAllowed | Self::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            )
                .into_response(),

            Self::UnsupportedTokenType => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnsupportedTokenType)),
            )
                .into_response(),

            // If the token is unknown, we still return a 200 OK response.
            Self::UnknownToken => StatusCode::OK.into_response(),
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl From<mas_data_model::TokenFormatError> for RouteError {
    fn from(_e: mas_data_model::TokenFormatError) -> Self {
        Self::UnknownToken
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.revoke.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
    err,
)]
pub(crate) async fn post(
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    mut repo: BoxRepository,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<RevocationRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    let token_type = TokenType::check(&form.token)?;

    // Find the ID of the session to end.
    let session_id = match (form.token_type_hint, token_type) {
        (Some(OAuthTokenTypeHint::AccessToken) | None, TokenType::AccessToken) => {
            let access_token = repo
                .oauth2_access_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::UnknownToken);
            }
            access_token.session_id
        }

        (Some(OAuthTokenTypeHint::RefreshToken) | None, TokenType::RefreshToken) => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !refresh_token.is_valid() {
                return Err(RouteError::UnknownToken);
            }

            refresh_token.session_id
        }

        // This case can happen if there is a mismatch between the token type hint and the guessed
        // token type or if the token was a compat access/refresh token. In those cases, we return
        // an unknown token error.
        (Some(OAuthTokenTypeHint::AccessToken | OAuthTokenTypeHint::RefreshToken) | None, _) => {
            return Err(RouteError::UnknownToken)
        }

        (Some(_), _) => return Err(RouteError::UnsupportedTokenType),
    };

    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::UnknownToken)?;

    // Check that the client ending the session is the same as the client that
    // created it.
    if client.id != session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    // Now that we checked eveyrthing, we can end the session.
    repo.oauth2_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_data_model::AuthorizationCode;
    use mas_router::SimpleRoute;
    use mas_storage::RepositoryAccess;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::{AccessTokenResponse, ResponseMode},
        scope::{Scope, OPENID},
    };
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_revoke_access_token(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let client_registration: ClientRegistrationResponse = response.json();

        let client_id = client_registration.client_id;
        let client_secret = client_registration.client_secret.unwrap();

        // Let's provision a user and create a session for them. This part is hard to
        // test with just HTTP requests, so we'll use the repository directly.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user)
            .await
            .unwrap();

        // Lookup the client in the database.
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        // Start a grant
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "thisisaverysecurecode".to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                None,
                ResponseMode::Query,
                false,
                false,
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .create_from_grant(&mut state.rng(), &state.clock, &grant, &browser_session)
            .await
            .unwrap();

        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&state.clock, &session, grant)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": grant.code.unwrap().code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let token: AccessTokenResponse = response.json();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&token.access_token).await);

        // Now let's revoke the access token.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": token.access_token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // Check that the token is no longer valid
        assert!(!state.is_access_token_valid(&token.access_token).await);

        // Try using the refresh token to get a new access token, it should fail.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": token.refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Now try with a new grant, and by revoking the refresh token instead
        let mut repo = state.repository().await.unwrap();
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "anotherverysecretcode".to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                None,
                ResponseMode::Query,
                false,
                false,
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .create_from_grant(&mut state.rng(), &state.clock, &grant, &browser_session)
            .await
            .unwrap();

        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&state.clock, &session, grant)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": grant.code.unwrap().code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let token: AccessTokenResponse = response.json();

        // Use the refresh token to get a new access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": token.refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let old_token = token;
        let token: AccessTokenResponse = response.json();
        assert!(state.is_access_token_valid(&token.access_token).await);
        assert!(!state.is_access_token_valid(&old_token.access_token).await);

        // Revoking the old access token shouldn't do anything.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": old_token.access_token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(state.is_access_token_valid(&token.access_token).await);

        // Revoking the old refresh token shouldn't do anything.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": old_token.refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(state.is_access_token_valid(&token.access_token).await);

        // Revoking the new refresh token should invalidate the session
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": token.refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(!state.is_access_token_valid(&token.access_token).await);
    }
}
