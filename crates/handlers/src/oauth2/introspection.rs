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

use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
    sentry::SentryEventID,
};
use mas_data_model::{TokenFormatError, TokenType};
use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_keystore::Encrypter;
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    user::UserRepository,
    BoxClock, BoxRepository, Clock,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{IntrospectionRequest, IntrospectionResponse},
    scope::ScopeToken,
};
use thiserror::Error;

use crate::{impl_from_error_for_route, ActivityTracker};

#[derive(Debug, Error)]
pub enum RouteError {
    /// An internal error occurred.
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The client could not be found.
    #[error("could not find client")]
    ClientNotFound,

    /// The client is not allowed to introspect.
    #[error("client is not allowed to introspect")]
    NotAllowed,

    /// The token type is not the one expected.
    #[error("unexpected token type")]
    UnexpectedTokenType,

    /// The overall token format is invalid.
    #[error("invalid token format")]
    InvalidTokenFormat(#[from] TokenFormatError),

    /// The token could not be found in the database.
    #[error("unknown {0}")]
    UnknownToken(TokenType),

    /// The token is not valid.
    #[error("{0} is not valid")]
    InvalidToken(TokenType),

    /// The OAuth session is not valid.
    #[error("invalid oauth session")]
    InvalidOAuthSession,

    /// The OAuth session could not be found in the database.
    #[error("unknown oauth session")]
    CantLoadOAuthSession,

    /// The compat session is not valid.
    #[error("invalid compat session")]
    InvalidCompatSession,

    /// The compat session could not be found in the database.
    #[error("unknown compat session")]
    CantLoadCompatSession,

    #[error("invalid user")]
    InvalidUser,

    #[error("unknown user")]
    CantLoadUser,

    #[error("bad request")]
    BadRequest,

    #[error(transparent)]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            e @ (Self::Internal(_)
            | Self::CantLoadCompatSession
            | Self::CantLoadOAuthSession
            | Self::CantLoadUser) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ),
            )
                .into_response(),
            Self::ClientNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),
            Self::ClientCredentialsVerification(e) => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClient)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),
            Self::UnknownToken(_)
            | Self::UnexpectedTokenType
            | Self::InvalidToken(_)
            | Self::InvalidUser
            | Self::InvalidCompatSession
            | Self::InvalidOAuthSession
            | Self::InvalidTokenFormat(_) => Json(INACTIVE).into_response(),
            Self::NotAllowed => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::AccessDenied)),
            )
                .into_response(),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

const INACTIVE: IntrospectionResponse = IntrospectionResponse {
    active: false,
    scope: None,
    client_id: None,
    username: None,
    token_type: None,
    exp: None,
    iat: None,
    nbf: None,
    sub: None,
    aud: None,
    iss: None,
    jti: None,
};

const API_SCOPE: ScopeToken = ScopeToken::from_static("urn:matrix:org.matrix.msc2967.client:api:*");
const SYNAPSE_ADMIN_SCOPE: ScopeToken = ScopeToken::from_static("urn:synapse:admin:*");

#[tracing::instrument(
    name = "handlers.oauth2.introspection.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
    err,
)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    mut repo: BoxRepository,
    activity_tracker: ActivityTracker,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<IntrospectionRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await
        .unwrap()
        .ok_or(RouteError::ClientNotFound)?;

    let method = match &client.token_endpoint_auth_method {
        None | Some(OAuthClientAuthenticationMethod::None) => {
            return Err(RouteError::NotAllowed);
        }
        Some(c) => c,
    };

    client_authorization
        .credentials
        .verify(&http_client_factory, &encrypter, method, &client)
        .await?;

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    let token = &form.token;
    let token_type = TokenType::check(token)?;
    if let Some(hint) = form.token_type_hint {
        if token_type != hint {
            return Err(RouteError::UnexpectedTokenType);
        }
    }

    // XXX: we should get the IP from the client introspecting the token
    let ip = None;

    let reply = match token_type {
        TokenType::AccessToken => {
            let access_token = repo
                .oauth2_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::InvalidOAuthSession)?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession);
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser)?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser);
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(access_token.jti()),
            }
        }

        TokenType::RefreshToken => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::RefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::RefreshToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadOAuthSession)?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession);
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser)?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser);
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(refresh_token.jti()),
            }
        }

        TokenType::CompatAccessToken => {
            let access_token = repo
                .compat_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatAccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::CompatAccessToken));
            }

            let session = repo
                .compat_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession)?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession);
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser)?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser)?;
            }

            // Grant the synapse admin scope if the session has the admin flag set.
            let synapse_admin = session.is_synapse_admin.then_some(SYNAPSE_ADMIN_SCOPE);
            let device_scope = session.device.to_scope_token();
            let scope = [API_SCOPE, device_scope]
                .into_iter()
                .chain(synapse_admin)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }

        TokenType::CompatRefreshToken => {
            let refresh_token = repo
                .compat_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatRefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::CompatRefreshToken));
            }

            let session = repo
                .compat_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession)?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession);
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser)?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser)?;
            }

            // Grant the synapse admin scope if the session has the admin flag set.
            let synapse_admin = session.is_synapse_admin.then_some(SYNAPSE_ADMIN_SCOPE);
            let device_scope = session.device.to_scope_token();
            let scope = [API_SCOPE, device_scope]
                .into_iter()
                .chain(synapse_admin)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
            }
        }
    };

    Ok(Json(reply))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{AccessToken, RefreshToken};
    use mas_iana::oauth::OAuthTokenTypeHint;
    use mas_router::{OAuth2Introspection, OAuth2RegistrationEndpoint, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::IntrospectionResponse,
        scope::{Scope, OPENID},
    };
    use serde_json::json;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        oauth2::generate_token_pair,
        test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_introspect_oauth_tokens(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client which will be used to do introspection requests
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "contacts": ["hello@introspecting.com"],
            "client_uri": "https://introspecting.com/",
            "grant_types": [],
            "token_endpoint_auth_method": "client_secret_basic",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let client: ClientRegistrationResponse = response.json();
        let introspecting_client_id = client.client_id;
        let introspecting_client_secret = client.client_secret.unwrap();

        // Provision a client which will be used to generate tokens
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "contacts": ["hello@client.com"],
            "client_uri": "https://client.com/",
            "redirect_uris": ["https://client.com/"],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        let mut repo = state.repository().await.unwrap();
        // Provision a user and an oauth session
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        let (AccessToken { access_token, .. }, RefreshToken { refresh_token, .. }) =
            generate_token_pair(
                &mut state.rng(),
                &state.clock,
                &mut repo,
                &session,
                Duration::minutes(5),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now that we have a token, we can introspect it
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some(client_id.clone()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::AccessToken));
        assert_eq!(response.scope, Some(Scope::from_iter([OPENID])));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Do the same, but with a refresh token
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some(client_id.clone()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::RefreshToken));
        assert_eq!(response.scope, Some(Scope::from_iter([OPENID])));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Advance the clock to invalidate the access token
        state.clock.advance(Duration::hours(1));

        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active anymore

        // But the refresh token should still be valid
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_introspect_compat_tokens(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client which will be used to do introspection requests
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "contacts": ["hello@introspecting.com"],
            "client_uri": "https://introspecting.com/",
            "grant_types": [],
            "token_endpoint_auth_method": "client_secret_basic",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let client: ClientRegistrationResponse = response.json();
        let introspecting_client_id = client.client_id;
        let introspecting_client_secret = client.client_secret.unwrap();

        // Provision a user with a password, so that we can use the password flow
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let (version, hashed_password) = state
            .password_manager
            .hash(&mut state.rng(), Zeroizing::new(b"password".to_vec()))
            .await
            .unwrap();

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock,
                &user,
                version,
                hashed_password,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now do a password flow to get an access token and a refresh token
        let request = Request::post("/_matrix/client/v3/login").json(json!({
            "type": "m.login.password",
            "refresh_token": true,
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: serde_json::Value = response.json();
        let access_token = response["access_token"].as_str().unwrap();
        let refresh_token = response["refresh_token"].as_str().unwrap();
        let device_id = response["device_id"].as_str().unwrap();
        let expected_scope: Scope =
            format!("urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:{device_id}")
                .parse()
                .unwrap();

        // Now that we have a token, we can introspect it
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some("legacy".to_owned()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::AccessToken));
        assert_eq!(response.scope, Some(expected_scope.clone()));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Do the same, but with a refresh token
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some("legacy".to_owned()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::RefreshToken));
        assert_eq!(response.scope, Some(expected_scope.clone()));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Advance the clock to invalidate the access token
        state.clock.advance(Duration::hours(1));

        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active anymore

        // But the refresh token should still be valid
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
    }
}
