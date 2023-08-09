// Copyright 2022 Kévin Commaille.
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

//! Requests for the [Authorization Code flow].
//!
//! [Authorization Code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth

use std::{collections::HashSet, num::NonZeroU32};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::header::CONTENT_TYPE;
use language_tags::LanguageTag;
use mas_http::{CatchHttpCodesLayer, FormUrlencodedRequestLayer, JsonResponseLayer};
use mas_iana::oauth::{OAuthAuthorizationEndpointResponseType, PkceCodeChallengeMethod};
use mas_jose::claims::{self, TokenHash};
use oauth2_types::{
    pkce,
    prelude::CodeChallengeMethodExt,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, AuthorizationRequest,
        Display, Prompt, PushedAuthorizationResponse,
    },
    scope::Scope,
};
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use serde::Serialize;
use serde_with::skip_serializing_none;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{
        AuthorizationError, IdTokenError, PushedAuthorizationError, TokenAuthorizationCodeError,
    },
    http_service::HttpService,
    requests::{jose::verify_id_token, token::request_access_token},
    types::{
        client_credentials::ClientCredentials,
        scope::{ScopeExt, ScopeToken},
        IdToken,
    },
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// The data necessary to build an authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestData {
    /// The ID obtained when registering the client.
    pub client_id: String,

    /// The scope to authorize.
    ///
    /// If the OpenID Connect scope token (`openid`) is not included, it will be
    /// added.
    pub scope: Scope,

    /// The URI to redirect the end-user to after the authorization.
    ///
    /// It must be one of the redirect URIs provided during registration.
    pub redirect_uri: Url,

    /// The PKCE methods supported by the issuer.
    ///
    /// This field should be cloned from the provider metadata. If it is not
    /// set, this security measure will not be used.
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

    /// How the Authorization Server should display the authentication and
    /// consent user interface pages to the End-User.
    pub display: Option<Display>,

    /// Whether the Authorization Server should prompt the End-User for
    /// reauthentication and consent.
    ///
    /// If [`Prompt::None`] is used, it must be the only value.
    pub prompt: Option<Vec<Prompt>>,

    /// The allowable elapsed time in seconds since the last time the End-User
    /// was actively authenticated by the OpenID Provider.
    pub max_age: Option<NonZeroU32>,

    /// End-User's preferred languages and scripts for the user interface.
    pub ui_locales: Option<Vec<LanguageTag>>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values.
    pub acr_values: Option<HashSet<String>>,
}

impl AuthorizationRequestData {
    /// Constructs a new `AuthorizationRequestData` with all the required
    /// fields.
    #[must_use]
    pub fn new(client_id: String, scope: Scope, redirect_uri: Url) -> Self {
        Self {
            client_id,
            scope,
            redirect_uri,
            code_challenge_methods_supported: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        }
    }

    /// Set the `code_challenge_methods_supported` field of this
    /// `AuthorizationRequestData`.
    #[must_use]
    pub fn with_code_challenge_methods_supported(
        mut self,
        code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
    ) -> Self {
        self.code_challenge_methods_supported = Some(code_challenge_methods_supported);
        self
    }

    /// Set the `display` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_display(mut self, display: Display) -> Self {
        self.display = Some(display);
        self
    }

    /// Set the `prompt` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_prompt(mut self, prompt: Vec<Prompt>) -> Self {
        self.prompt = Some(prompt);
        self
    }

    /// Set the `max_age` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_max_age(mut self, max_age: NonZeroU32) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Set the `ui_locales` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_ui_locales(mut self, ui_locales: Vec<LanguageTag>) -> Self {
        self.ui_locales = Some(ui_locales);
        self
    }

    /// Set the `id_token_hint` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_id_token_hint(mut self, id_token_hint: String) -> Self {
        self.id_token_hint = Some(id_token_hint);
        self
    }

    /// Set the `login_hint` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: String) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    /// Set the `acr_values` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_acr_values(mut self, acr_values: HashSet<String>) -> Self {
        self.acr_values = Some(acr_values);
        self
    }
}

/// The data necessary to validate a response from the Token endpoint in the
/// Authorization Code flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationValidationData {
    /// A unique identifier for the request.
    pub state: String,

    /// A string to mitigate replay attacks.
    pub nonce: String,

    /// The URI where the end-user will be redirected after authorization.
    pub redirect_uri: Url,

    /// A string to correlate the authorization request to the token request.
    pub code_challenge_verifier: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize)]
struct FullAuthorizationRequest {
    #[serde(flatten)]
    inner: AuthorizationRequest,
    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Build the authorization request.
fn build_authorization_request(
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(FullAuthorizationRequest, AuthorizationValidationData), AuthorizationError> {
    let AuthorizationRequestData {
        client_id,
        mut scope,
        redirect_uri,
        code_challenge_methods_supported,
        display,
        prompt,
        max_age,
        ui_locales,
        id_token_hint,
        login_hint,
        acr_values,
    } = authorization_data;

    // Generate a random CSRF "state" token and a nonce.
    let state = Alphanumeric.sample_string(rng, 16);
    let nonce = Alphanumeric.sample_string(rng, 16);

    // Use PKCE, whenever possible.
    let (pkce, code_challenge_verifier) = if code_challenge_methods_supported
        .iter()
        .any(|methods| methods.contains(&PkceCodeChallengeMethod::S256))
    {
        let mut verifier = [0u8; 32];
        rng.fill(&mut verifier);

        let method = PkceCodeChallengeMethod::S256;
        let verifier = Base64UrlUnpadded::encode_string(&verifier);
        let code_challenge = method.compute_challenge(&verifier)?.into();

        let pkce = pkce::AuthorizationRequest {
            code_challenge_method: method,
            code_challenge,
        };

        (Some(pkce), Some(verifier))
    } else {
        (None, None)
    };

    scope.insert_token(ScopeToken::Openid);

    let auth_request = FullAuthorizationRequest {
        inner: AuthorizationRequest {
            response_type: OAuthAuthorizationEndpointResponseType::Code.into(),
            client_id,
            redirect_uri: Some(redirect_uri.clone()),
            scope,
            state: Some(state.clone()),
            response_mode: None,
            nonce: Some(nonce.clone()),
            display,
            prompt,
            max_age,
            ui_locales,
            id_token_hint,
            login_hint,
            acr_values,
            request: None,
            request_uri: None,
            registration: None,
        },
        pkce,
    };

    let auth_data = AuthorizationValidationData {
        state,
        nonce,
        redirect_uri,
        code_challenge_verifier,
    };

    Ok((auth_request, auth_data))
}

/// Build the URL for authenticating at the Authorization endpoint.
///
/// # Arguments
///
/// * `authorization_endpoint` - The URL of the issuer's authorization endpoint.
///
/// * `authorization_data` - The data necessary to build the authorization
///   request.
///
/// * `rng` - A random number generator.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// authorize the given scope, and the [`AuthorizationValidationData`] to
/// validate this request.
///
/// The redirect URI will receive parameters in its query:
///
/// * A successful response will receive a `code` and a `state`.
///
/// * If the authorization fails, it should receive an `error` parameter with a
///   [`ClientErrorCode`] and optionally an `error_description`.
///
/// # Errors
///
/// Returns an error if preparing the URL fails.
///
/// [`VerifiedClientMetadata`]: oauth2_types::registration::VerifiedClientMetadata
/// [`ClientErrorCode`]: oauth2_types::errors::ClientErrorCode
#[allow(clippy::too_many_lines)]
pub fn build_authorization_url(
    authorization_endpoint: Url,
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(Url, AuthorizationValidationData), AuthorizationError> {
    tracing::debug!(
        scope = ?authorization_data.scope,
        "Authorizing..."
    );

    let (authorization_request, validation_data) =
        build_authorization_request(authorization_data, rng)?;

    let authorization_query = serde_urlencoded::to_string(authorization_request)?;

    let mut authorization_url = authorization_endpoint;

    // Add our parameters to the query, because the URL might already have one.
    let mut full_query = authorization_url
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if !full_query.is_empty() {
        full_query.push('&');
    }
    full_query.push_str(&authorization_query);

    authorization_url.set_query(Some(&full_query));

    Ok((authorization_url, validation_data))
}

/// Make a [Pushed Authorization Request] and build the URL for authenticating
/// at the Authorization endpoint.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `par_endpoint` - The URL of the issuer's Pushed Authorization Request
///   endpoint.
///
/// * `authorization_endpoint` - The URL of the issuer's Authorization endpoint.
///
/// * `authorization_data` - The data necessary to build the authorization
///   request.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// authorize the given scope, and the [`AuthorizationValidationData`] to
/// validate this request.
///
/// The redirect URI will receive parameters in its query:
///
/// * A successful response will receive a `code` and a `state`.
///
/// * If the authorization fails, it should receive an `error` parameter with a
///   [`ClientErrorCode`] and optionally an `error_description`.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or building
/// the URL fails.
///
/// [Pushed Authorization Request]: https://oauth.net/2/pushed-authorization-requests/
/// [`ClientErrorCode`]: oauth2_types::errors::ClientErrorCode
#[tracing::instrument(skip_all, fields(par_endpoint))]
pub async fn build_par_authorization_url(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    par_endpoint: &Url,
    authorization_endpoint: Url,
    authorization_data: AuthorizationRequestData,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(Url, AuthorizationValidationData), AuthorizationError> {
    tracing::debug!(
        scope = ?authorization_data.scope,
        "Authorizing with a PAR..."
    );

    let client_id = client_credentials.client_id().to_owned();

    let (authorization_request, validation_data) =
        build_authorization_request(authorization_data, rng)?;

    let par_request = http::Request::post(par_endpoint.as_str())
        .header(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())
        .body(authorization_request)
        .map_err(PushedAuthorizationError::from)?;

    let par_request = client_credentials
        .apply_to_request(par_request, now, rng)
        .map_err(PushedAuthorizationError::from)?;

    let service = (
        FormUrlencodedRequestLayer::default(),
        JsonResponseLayer::<PushedAuthorizationResponse>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let par_response = service
        .ready_oneshot()
        .await
        .map_err(PushedAuthorizationError::from)?
        .call(par_request)
        .await
        .map_err(PushedAuthorizationError::from)?
        .into_body();

    let authorization_query = serde_urlencoded::to_string([
        ("request_uri", par_response.request_uri.as_str()),
        ("client_id", &client_id),
    ])?;

    let mut authorization_url = authorization_endpoint;

    // Add our parameters to the query, because the URL might already have one.
    let mut full_query = authorization_url
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if !full_query.is_empty() {
        full_query.push('&');
    }
    full_query.push_str(&authorization_query);

    authorization_url.set_query(Some(&full_query));

    Ok((authorization_url, validation_data))
}

/// Exchange an authorization code for an access token.
///
/// This should be used as the first step for logging in, and to request a
/// token with a new scope.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `token_endpoint` - The URL of the issuer's Token endpoint.
///
/// * `code` - The authorization code returned at the Authorization endpoint.
///
/// * `validation_data` - The validation data that was returned when building
///   the Authorization URL, for the state returned at the Authorization
///   endpoint.
///
/// * `id_token_verification_data` - The data required to verify the ID Token in
///   the response.
///
///   The signing algorithm corresponds to the `id_token_signed_response_alg`
///   field in the client metadata.
///
///   If it is not provided, the ID Token won't be verified. Note that in the
///   OpenID Connect specification, this verification is required.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// verification of the ID Token fails.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(token_endpoint))]
pub async fn access_token_with_authorization_code(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    code: String,
    validation_data: AuthorizationValidationData,
    id_token_verification_data: Option<JwtVerificationData<'_>>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(AccessTokenResponse, Option<IdToken<'static>>), TokenAuthorizationCodeError> {
    tracing::debug!("Exchanging authorization code for access token...");

    let token_response = request_access_token(
        http_service,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: code.clone(),
            redirect_uri: Some(validation_data.redirect_uri),
            code_verifier: validation_data.code_challenge_verifier,
        }),
        now,
        rng,
    )
    .await?;

    let id_token = if let Some(verification_data) = id_token_verification_data {
        let signing_alg = verification_data.signing_algorithm;

        let id_token = token_response
            .id_token
            .as_deref()
            .ok_or(IdTokenError::MissingIdToken)?;

        let id_token = verify_id_token(id_token, verification_data, None, now)?;

        let mut claims = id_token.payload().clone();

        // Access token hash must match.
        claims::AT_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(signing_alg, &token_response.access_token),
            )
            .map_err(IdTokenError::from)?;

        // Code hash must match.
        claims::C_HASH
            .extract_optional_with_options(&mut claims, TokenHash::new(signing_alg, &code))
            .map_err(IdTokenError::from)?;

        // Nonce must match.
        claims::NONCE
            .extract_required_with_options(&mut claims, validation_data.nonce.as_str())
            .map_err(IdTokenError::from)?;

        Some(id_token.into_owned())
    } else {
        None
    };

    Ok((token_response, id_token))
}
