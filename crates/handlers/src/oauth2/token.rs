// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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
use chrono::{DateTime, Duration, Utc};
use headers::{CacheControl, HeaderMap, HeaderMapExt, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    http_client_factory::HttpClientFactory,
    sentry::SentryEventID,
};
use mas_data_model::{
    AuthorizationGrantStage, Client, Device, DeviceCodeGrantState, TokenType, UserAgent,
};
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::types::scope::ScopeToken;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionDeviceJob},
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    user::BrowserSessionRepository,
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce::CodeChallengeError,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant,
        DeviceCodeGrant, GrantType, RefreshTokenGrant,
    },
    scope,
};
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none};
use thiserror::Error;
use tracing::debug;
use ulid::Ulid;
use url::Url;

use super::{generate_id_token, generate_token_pair};
use crate::{impl_from_error_for_route, site_config::SiteConfig, BoundActivityTracker};

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Debug)]
struct CustomClaims {
    #[serde(rename = "iss")]
    issuer: Url,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "aud")]
    audiences: Vec<String>,
    nonce: Option<String>,
    #[serde_as(as = "Option<serde_with::TimestampSeconds>")]
    auth_time: Option<DateTime<Utc>>,
    at_hash: String,
    c_hash: String,
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("could not verify client credentials")]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("grant not found")]
    GrantNotFound,

    #[error("invalid grant")]
    InvalidGrant,

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIDMismatch { expected: Ulid, actual: Ulid },

    #[error("policy denied the request")]
    DeniedByPolicy(Vec<mas_policy::Violation>),

    #[error("unsupported grant type")]
    UnsupportedGrantType,

    #[error("unauthorized client")]
    UnauthorizedClient,

    #[error("failed to load browser session")]
    NoSuchBrowserSession,

    #[error("failed to load oauth session")]
    NoSuchOAuthSession,

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);

        let response = match self {
            Self::Internal(_) | Self::NoSuchBrowserSession | Self::NoSuchOAuthSession => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            ),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            ),
            Self::PkceVerification(err) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description(format!("PKCE verification failed: {err}")),
                ),
            ),
            Self::ClientNotFound | Self::ClientCredentialsVerification(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            ),
            Self::ClientNotAllowed | Self::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),
            Self::DeniedByPolicy(violations) => (
                StatusCode::FORBIDDEN,
                Json(
                    ClientError::from(ClientErrorCode::InvalidScope).with_description(
                        violations
                            .into_iter()
                            .map(|violation| violation.msg)
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ),
            ),
            Self::DeviceCodeRejected => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::AccessDenied)),
            ),
            Self::DeviceCodeExpired => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::ExpiredToken)),
            ),
            Self::DeviceCodePending => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::AuthorizationPending)),
            ),
            Self::InvalidGrant
            | Self::DeviceCodeExchanged
            | Self::RefreshTokenNotFound
            | Self::RefreshTokenInvalid(_)
            | Self::SessionInvalid(_)
            | Self::ClientIDMismatch { .. }
            | Self::GrantNotFound => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidGrant)),
            ),
            Self::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnsupportedGrantType)),
            ),
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(super::IdTokenSignatureError);

#[tracing::instrument(
    name = "handlers.oauth2.token.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
    err,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(encrypter): State<Encrypter>,
    policy: Policy,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    client_authorization: ClientAuthorization<AccessTokenRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
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

    let form = client_authorization.form.ok_or(RouteError::BadRequest)?;

    let (reply, repo) = match form {
        AccessTokenRequest::AuthorizationCode(grant) => {
            authorization_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &key_store,
                &url_builder,
                &site_config,
                repo,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::RefreshToken(grant) => {
            refresh_token_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &site_config,
                repo,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::ClientCredentials(grant) => {
            client_credentials_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &site_config,
                repo,
                policy,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::DeviceCode(grant) => {
            device_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &key_store,
                &url_builder,
                &site_config,
                repo,
                user_agent,
            )
            .await?
        }
        _ => {
            return Err(RouteError::UnsupportedGrantType);
        }
    };

    repo.save().await?;

    let mut headers = HeaderMap::new();
    headers.typed_insert(CacheControl::new().with_no_store());
    headers.typed_insert(Pragma::no_cache());

    Ok((headers, Json(reply)))
}

#[allow(clippy::too_many_lines)] // TODO: refactor some parts out
async fn authorization_code_grant(
    mut rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<UserAgent>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(RouteError::UnauthorizedClient);
    }

    let authz_grant = repo
        .oauth2_authorization_grant()
        .find_by_code(&grant.code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let now = clock.now();

    let session_id = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session_id,
        } => {
            debug!(%exchanged_at, %fulfilled_at, "Authorization code was already exchanged");

            // Ending the session if the token was already exchanged more than 20s ago
            if now - exchanged_at > Duration::microseconds(20 * 1000 * 1000) {
                debug!("Ending potentially compromised session");
                let session = repo
                    .oauth2_session()
                    .lookup(session_id)
                    .await?
                    .ok_or(RouteError::NoSuchOAuthSession)?;
                repo.oauth2_session().finish(clock, session).await?;
                repo.save().await?;
            }

            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Pending => {
            debug!("Authorization grant has not been fulfilled yet");
            return Err(RouteError::InvalidGrant);
        }
        AuthorizationGrantStage::Fulfilled {
            session_id,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::microseconds(10 * 60 * 1000 * 1000) {
                debug!("Code exchange took more than 10 minutes");
                return Err(RouteError::InvalidGrant);
            }

            session_id
        }
    };

    let mut session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession)?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    // This should never happen, since we looked up in the database using the code
    let code = authz_grant.code.as_ref().ok_or(RouteError::InvalidGrant)?;

    if client.id != session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return Err(RouteError::BadRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            pkce.verify(verifier)?;
        }
    };

    let Some(user_session_id) = session.user_session_id else {
        tracing::warn!("No user session associated with this OAuth2 session");
        return Err(RouteError::InvalidGrant);
    };

    let browser_session = repo
        .browser_session()
        .lookup(user_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession)?;

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = site_config.access_token_ttl;
    let (access_token, refresh_token) =
        generate_token_pair(&mut rng, clock, &mut repo, &session, ttl).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        Some(generate_id_token(
            &mut rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&authz_grant),
            &browser_session,
            Some(&access_token),
            last_authentication.as_ref(),
        )?)
    } else {
        None
    };

    let mut params = AccessTokenResponse::new(access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.refresh_token)
        .with_scope(session.scope.clone());

    if let Some(id_token) = id_token {
        params = params.with_id_token(id_token);
    }

    // Look for device to provision
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            // Note that we're not waiting for the job to finish, we just schedule it. We
            // might get in a situation where the provisioning job is not finished when the
            // client does its first request to the Homeserver. This is fine for now, since
            // Synapse still provision devices on-the-fly if it doesn't find them in the
            // database.
            repo.job()
                .schedule_job(ProvisionDeviceJob::new(&browser_session.user, &device))
                .await?;
        }
    }

    repo.oauth2_authorization_grant()
        .exchange(clock, authz_grant)
        .await?;

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    Ok((params, repo))
}

async fn refresh_token_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &RefreshTokenGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<UserAgent>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(RouteError::UnauthorizedClient);
    }

    let refresh_token = repo
        .oauth2_refresh_token()
        .find_by_token(&grant.refresh_token)
        .await?
        .ok_or(RouteError::RefreshTokenNotFound)?;

    let mut session = repo
        .oauth2_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession)?;

    // Let's for now record the user agent on each refresh, that should be
    // responsive enough and not too much of a burden on the database.
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    if !refresh_token.is_valid() {
        return Err(RouteError::RefreshTokenInvalid(refresh_token.id));
    }

    if !session.is_valid() {
        return Err(RouteError::SessionInvalid(session.id));
    }

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RouteError::ClientIDMismatch {
            expected: session.client_id,
            actual: client.id,
        });
    }

    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    let ttl = site_config.access_token_ttl;
    let (new_access_token, new_refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let refresh_token = repo
        .oauth2_refresh_token()
        .consume(clock, refresh_token)
        .await?;

    if let Some(access_token_id) = refresh_token.access_token_id {
        let access_token = repo.oauth2_access_token().lookup(access_token_id).await?;
        if let Some(access_token) = access_token {
            repo.oauth2_access_token()
                .revoke(clock, access_token)
                .await?;
        }
    }

    let params = AccessTokenResponse::new(new_access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(new_refresh_token.refresh_token)
        .with_scope(session.scope);

    Ok((params, repo))
}

async fn client_credentials_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &ClientCredentialsGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<UserAgent>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(RouteError::UnauthorizedClient);
    }

    // Default to an empty scope if none is provided
    let scope = grant
        .scope
        .clone()
        .unwrap_or_else(|| std::iter::empty::<ScopeToken>().collect());

    // Make the request go through the policy engine
    let res = policy
        .evaluate_client_credentials_grant(&scope, client)
        .await?;
    if !res.valid() {
        return Err(RouteError::DeniedByPolicy(res.violations));
    }

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_client_credentials(rng, clock, client, scope)
        .await?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params = AccessTokenResponse::new(access_token.access_token).with_expires_in(ttl);

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

async fn device_code_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &DeviceCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<UserAgent>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::UnauthorizedClient);
    }

    let grant = repo
        .oauth2_device_code_grant()
        .find_by_device_code(&grant.device_code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    // Check that the client match
    if client.id != grant.client_id {
        return Err(RouteError::ClientIDMismatch {
            expected: grant.client_id,
            actual: client.id,
        });
    }

    if grant.expires_at < clock.now() {
        return Err(RouteError::DeviceCodeExpired);
    }

    let browser_session_id = match &grant.state {
        DeviceCodeGrantState::Pending => {
            return Err(RouteError::DeviceCodePending);
        }
        DeviceCodeGrantState::Rejected { .. } => {
            return Err(RouteError::DeviceCodeRejected);
        }
        DeviceCodeGrantState::Exchanged { .. } => {
            return Err(RouteError::DeviceCodeExchanged);
        }
        DeviceCodeGrantState::Fulfilled {
            browser_session_id, ..
        } => browser_session_id,
    };

    let browser_session = repo
        .browser_session()
        .lookup(*browser_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession)?;

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_browser_session(rng, clock, client, &browser_session, grant.scope)
        .await?;

    // XXX: should we get the user agent from the device code grant instead?
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params =
        AccessTokenResponse::new(access_token.access_token.clone()).with_expires_in(ttl);

    // If the client uses the refresh token grant type, we also generate a refresh
    // token
    if client.grant_types.contains(&GrantType::RefreshToken) {
        let refresh_token_str = TokenType::RefreshToken.generate(rng);

        let refresh_token = repo
            .oauth2_refresh_token()
            .add(rng, clock, &session, &access_token, refresh_token_str)
            .await?;

        params = params.with_refresh_token(refresh_token.refresh_token);
    }

    // If the client asked for an ID token, we generate one
    if session.scope.contains(&scope::OPENID) {
        let id_token = generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            None,
            &browser_session,
            Some(&access_token),
            None,
        )?;

        params = params.with_id_token(id_token);
    }

    // Look for device to provision
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            // Note that we're not waiting for the job to finish, we just schedule it. We
            // might get in a situation where the provisioning job is not finished when the
            // client does its first request to the Homeserver. This is fine for now, since
            // Synapse still provision devices on-the-fly if it doesn't find them in the
            // database.
            repo.job()
                .schedule_job(ProvisionDeviceJob::new(&browser_session.user, &device))
                .await?;
        }
    }

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_data_model::{AccessToken, AuthorizationCode, RefreshToken};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::{DeviceAuthorizationResponse, ResponseMode},
        scope::{Scope, OPENID},
    };
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_auth_code_grant(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

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
            .add(&mut state.rng(), &state.clock, &user, None)
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
        let code = "thisisaverysecurecode";
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: code.to_owned(),
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
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // And fulfill it
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
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let AccessTokenResponse { access_token, .. } = response.json();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Exchange it again, this it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidGrant);

        // The token should still be valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now wait a bit
        state.clock.advance(Duration::try_minutes(1).unwrap());

        // Exchange it again, this it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidGrant);

        // And it should have revoked the token we got
        assert!(!state.is_access_token_valid(&access_token).await);

        // Try another one and wait for too long before exchanging it
        let mut repo = state.repository().await.unwrap();
        let code = "thisisanothercode";
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: code.to_owned(),
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
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // And fulfill it
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&state.clock, &session, grant)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now wait a bit
        state
            .clock
            .advance(Duration::microseconds(15 * 60 * 1000 * 1000));

        // Exchange it, it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidGrant);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_refresh_token_grant(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

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
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        // Lookup the client in the database.
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        // Get a token pair
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
                Duration::microseconds(5 * 60 * 1000 * 1000),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // First check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let old_access_token = access_token;
        let old_refresh_token = refresh_token;
        let response: AccessTokenResponse = response.json();
        let access_token = response.access_token;
        let refresh_token = response.refresh_token.expect("to have a refresh token");

        // Check that the new token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Check that the old token is no longer valid
        assert!(!state.is_access_token_valid(&old_access_token).await);

        // Call it again with the old token, it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": old_refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidGrant);

        // Call it again with the new token, it should work
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let _: AccessTokenResponse = response.json();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_client_credentials(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["client_credentials"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;
        let client_secret = response.client_secret.expect("to have a client secret");

        // Call the token endpoint with an empty scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert!(response.scope.is_none());

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // We should be allowed to ask for the GraphQL API scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:graphql:*"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert_eq!(response.scope, Some("urn:mas:graphql:*".parse().unwrap()));

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // We should be NOT allowed to ask for the MAS admin scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:admin"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidScope);

        // Now, if we add the client to the admin list in the policy, it should work
        let state = {
            let mut state = state;
            state.policy_factory = crate::test_utils::policy_factory(serde_json::json!({
                "admin_clients": [client_id]
            }))
            .await
            .unwrap();
            state
        };

        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:admin"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert_eq!(response.scope, Some("urn:mas:admin".parse().unwrap()));

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_device_code_grant(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;

        // Start a device code grant
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Poll the token endpoint, it should be pending
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AuthorizationPending);

        // Let's provision a user and create a browser session for them. This part is
        // hard to test with just HTTP requests, so we'll use the repository
        // directly.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        // Find the grant
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&device_grant.user_code)
            .await
            .unwrap()
            .unwrap();

        // And fulfill it
        let grant = repo
            .oauth2_device_code_grant()
            .fulfill(&state.clock, grant, &browser_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant.device_code,
                "client_id": client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&response.access_token).await);
        // We advertised the refresh token grant type, so we should have a refresh token
        assert!(response.refresh_token.is_some());
        // We asked for the openid scope, so we should have an ID token
        assert!(response.id_token.is_some());

        // Do another grant and make it expire
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Poll the token endpoint, it should be pending
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AuthorizationPending);

        state.clock.advance(Duration::try_hours(1).unwrap());

        // Poll again, it should be expired
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::ExpiredToken);

        // Do another grant and reject it
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Find the grant and reject it
        let mut repo = state.repository().await.unwrap();

        // Find the grant
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&device_grant.user_code)
            .await
            .unwrap()
            .unwrap();

        // And reject it
        let grant = repo
            .oauth2_device_code_grant()
            .reject(&state.clock, grant, &browser_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Poll the token endpoint, it should be rejected
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AccessDenied);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unsupported_grant(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "contacts": ["contact@example.com"],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["password"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;
        let client_secret = response.client_secret.expect("to have a client secret");

        // Call the token endpoint with an unsupported grant type
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": "john",
                "password": "hunter2",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::UnsupportedGrantType);
    }
}
