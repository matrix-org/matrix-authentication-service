// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::{collections::HashSet, hash::Hash, num::NonZeroU32};

use chrono::{DateTime, Duration, Utc};
use language_tags::LanguageTag;
use mas_iana::oauth::{OAuthAccessTokenType, OAuthTokenTypeHint};
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{
    formats::SpaceSeparator, serde_as, skip_serializing_none, DeserializeFromStr, DisplayFromStr,
    DurationSeconds, SerializeDisplay, StringWithSeparator, TimestampSeconds,
};
use url::Url;

use crate::{response_type::ResponseType, scope::Scope};

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

/// The mechanism to be used for returning Authorization Response parameters
/// from the Authorization Endpoint.
///
/// Defined in [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes).
#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[display(style = "snake_case")]
pub enum ResponseMode {
    /// Authorization Response parameters are encoded in the query string added
    /// to the `redirect_uri`.
    Query,

    /// Authorization Response parameters are encoded in the fragment added to
    /// the `redirect_uri`.
    Fragment,

    /// Authorization Response parameters are encoded as HTML form values that
    /// are auto-submitted in the User Agent, and thus are transmitted via the
    /// HTTP `POST` method to the Client, with the result parameters being
    /// encoded in the body using the `application/x-www-form-urlencoded`
    /// format.
    ///
    /// Defined in [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
    FormPost,
}

/// Value that specifies how the Authorization Server displays the
/// authentication and consent user interface pages to the End-User.
///
/// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[display(style = "snake_case")]
pub enum Display {
    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a full User Agent page view.
    ///
    /// This is the default display mode.
    Page,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a popup User Agent window.
    Popup,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a device that leverages a touch interface.
    Touch,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a "feature phone" type display.
    Wap,
}

impl Default for Display {
    fn default() -> Self {
        Self::Page
    }
}

/// Value that specifies whether the Authorization Server prompts the End-User
/// for reauthentication and consent.
///
/// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[display(style = "snake_case")]
pub enum Prompt {
    /// The Authorization Server must not display any authentication or consent
    /// user interface pages.
    None,

    /// The Authorization Server should prompt the End-User for
    /// reauthentication.
    Login,

    /// The Authorization Server should prompt the End-User for consent before
    /// returning information to the Client.
    Consent,

    /// The Authorization Server should prompt the End-User to select a user
    /// account.
    ///
    /// This enables an End-User who has multiple accounts at the Authorization
    /// Server to select amongst the multiple accounts that they might have
    /// current sessions for.
    SelectAccount,

    /// The Authorization Server should prompt the End-User to create a user
    /// account.
    ///
    /// Defined in [Initiating User Registration via OpenID Connect](https://openid.net/specs/openid-connect-prompt-create-1_0.html).
    Create,
}

/// The body of a request to the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizationRequest {
    /// OAuth 2.0 Response Type value that determines the authorization
    /// processing flow to be used.
    pub response_type: ResponseType,

    /// OAuth 2.0 Client Identifier valid at the Authorization Server.
    pub client_id: String,

    /// Redirection URI to which the response will be sent.
    ///
    /// This field is required when using a response type returning an
    /// authorization code.
    ///
    /// This URI must have been pre-registered with the OpenID Provider.
    pub redirect_uri: Option<Url>,

    /// The scope of the access request.
    ///
    /// OpenID Connect requests must contain the `openid` scope value.
    pub scope: Scope,

    /// Opaque value used to maintain state between the request and the
    /// callback.
    pub state: Option<String>,

    /// The mechanism to be used for returning parameters from the Authorization
    /// Endpoint.
    ///
    /// This use of this parameter is not recommended when the Response Mode
    /// that would be requested is the default mode specified for the Response
    /// Type.
    pub response_mode: Option<ResponseMode>,

    /// String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks.
    pub nonce: Option<String>,

    /// How the Authorization Server should display the authentication and
    /// consent user interface pages to the End-User.
    pub display: Option<Display>,

    /// Whether the Authorization Server should prompt the End-User for
    /// reauthentication and consent.
    ///
    /// If [`Prompt::None`] is used, it must be the only value.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, Prompt>>")]
    #[serde(default)]
    pub prompt: Option<Vec<Prompt>>,

    /// The allowable elapsed time in seconds since the last time the End-User
    /// was actively authenticated by the OpenID Provider.
    #[serde(default)]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub max_age: Option<NonZeroU32>,

    /// End-User's preferred languages and scripts for the user interface.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    pub ui_locales: Option<Vec<LanguageTag>>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    #[serde(default)]
    pub acr_values: Option<HashSet<String>>,

    /// A JWT that contains the request's parameter values, called a [Request
    /// Object].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
    pub request: Option<String>,

    /// A URI referencing a [Request Object] or a [Pushed Authorization
    /// Request].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter
    /// [Pushed Authorization Request]: https://datatracker.ietf.org/doc/html/rfc9126
    pub request_uri: Option<Url>,

    /// A JSON object containing the Client Metadata when interacting with a
    /// [Self-Issued OpenID Provider].
    ///
    /// [Self-Issued OpenID Provider]: https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
    pub registration: Option<String>,
}

impl AuthorizationRequest {
    /// Creates a basic `AuthorizationRequest`.
    #[must_use]
    pub fn new(response_type: ResponseType, client_id: String, scope: Scope) -> Self {
        Self {
            response_type,
            client_id,
            redirect_uri: None,
            scope,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            request: None,
            request_uri: None,
            registration: None,
        }
    }
}

/// A successful response from the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct AuthorizationResponse<R> {
    pub code: Option<String>,
    #[serde(flatten)]
    pub response: R,
}

/// A request to the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

pub const DEFAULT_DEVICE_AUTHORIZATION_INTERVAL_SECONDS: i64 = 5;

/// A successful response from the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    device_code: String,

    /// The end-user verification code.
    user_code: String,

    /// The end-user verification URI on the authorization server.
    ///
    /// The URI should be short and easy to remember as end users will be asked
    /// to manually type it into their user agent.
    verification_uri: Url,

    /// A verification URI that includes the `user_code` (or other information
    /// with the same function as the `user_code`), which is designed for
    /// non-textual transmission.
    verification_uri_complete: Option<Url>,

    /// The lifetime of the `device_code` and `user_code`.
    #[serde_as(as = "DurationSeconds<i64>")]
    expires_in: Duration,

    /// The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL_SECONDS`].
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    interval: Option<Duration>,
}

impl DeviceAuthorizationResponse {
    ///The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL_SECONDS`].
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
            .unwrap_or_else(|| Duration::seconds(DEFAULT_DEVICE_AUTHORIZATION_INTERVAL_SECONDS))
    }
}

/// A request to the [Token Endpoint] for the [Authorization Code] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Authorization Code]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    /// The authorization code that was returned from the authorization
    /// endpoint.
    pub code: String,

    /// The `redirect_uri` that was included in the authorization request.
    ///
    /// This field must match exactly the value passed to the authorization
    /// endpoint.
    pub redirect_uri: Option<Url>,

    /// The code verifier that matches the code challenge that was sent to the
    /// authorization endpoint.
    // TODO: move this somehow in the pkce module
    pub code_verifier: Option<String>,
}

/// A request to the [Token Endpoint] for [refreshing an access token].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [refreshing an access token]: https://www.rfc-editor.org/rfc/rfc6749#section-6
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenGrant {
    /// The refresh token issued to the client.
    pub refresh_token: String,

    /// The scope of the access request.
    ///
    /// The requested scope must not include any scope not originally granted by
    /// the resource owner, and if omitted is treated as equal to the scope
    /// originally granted by the resource owner.
    pub scope: Option<Scope>,
}

/// A request to the [Token Endpoint] for the [Client Credentials] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Client Credentials]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsGrant {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

/// A request to the [Token Endpoint] for the [Device Authorization] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Device Authorization]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceCodeGrant {
    /// The device verification code, from the device authorization response.
    pub device_code: Option<Scope>,
}

/// All possible values for the `grant_type` parameter.
#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[display(style = "snake_case")]
pub enum GrantType {
    /// [`authorization_code`](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
    AuthorizationCode,

    /// [`refresh_token`](https://www.rfc-editor.org/rfc/rfc6749#section-6)
    RefreshToken,

    /// [`implicit`](https://www.rfc-editor.org/rfc/rfc6749#section-4.2)
    Implicit,

    /// [`client_credentials`](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
    ClientCredentials,

    /// [`password`](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)
    Password,

    /// [`urn:ietf:params:oauth:grant-type:device_code`](https://www.rfc-editor.org/rfc/rfc8628)
    #[display("urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,

    /// [`urn:openid:params:grant-type:ciba`](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
    #[display("urn:openid:params:grant-type:ciba")]
    ClientInitiatedBackchannelAuthentication,
}

/// An enum representing the possible requests to the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum AccessTokenRequest {
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
    ClientCredentials(ClientCredentialsGrant),
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),
    #[serde(skip, other)]
    Unsupported,
}

/// A successful response from the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenResponse {
    /// The access token to access the requested scope.
    pub access_token: String,

    /// The token to refresh the access token when it expires.
    pub refresh_token: Option<String>,

    /// ID Token value associated with the authenticated session.
    // TODO: this should be somewhere else
    pub id_token: Option<String>,

    /// The type of the access token.
    pub token_type: OAuthAccessTokenType,

    /// The duration for which the access token is valid.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,

    /// The scope of the access token.
    pub scope: Option<Scope>,
}

impl AccessTokenResponse {
    /// Creates a new `AccessTokenResponse` with the given access token.
    #[must_use]
    pub fn new(access_token: String) -> AccessTokenResponse {
        AccessTokenResponse {
            access_token,
            refresh_token: None,
            id_token: None,
            token_type: OAuthAccessTokenType::Bearer,
            expires_in: None,
            scope: None,
        }
    }

    /// Adds a refresh token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// Adds an ID token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }

    /// Adds a scope to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Adds an expiration duration to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }
}

/// A request to the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionRequest {
    /// The value of the token.
    pub token: String,

    /// A hint about the type of the token submitted for introspection.
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

/// A successful response from the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrospectionResponse {
    /// Whether or not the presented token is currently active.
    pub active: bool,

    /// The scope associated with the token.
    pub scope: Option<Scope>,

    /// Client identifier for the OAuth 2.0 client that requested this token.
    pub client_id: Option<String>,

    /// Human-readable identifier for the resource owner who authorized this
    /// token.
    pub username: Option<String>,

    /// Type of the token.
    pub token_type: Option<OAuthTokenTypeHint>,

    /// Timestamp indicating when the token will expire.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub exp: Option<DateTime<Utc>>,

    /// Timestamp indicating when the token was issued.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub iat: Option<DateTime<Utc>>,

    /// Timestamp indicating when the token is not to be used before.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub nbf: Option<DateTime<Utc>>,

    /// Subject of the token.
    pub sub: Option<String>,

    /// Intended audience of the token.
    pub aud: Option<String>,

    /// Issuer of the token.
    pub iss: Option<String>,

    /// String identifier for the token.
    pub jti: Option<String>,
}

/// A successful response from the [Pushed Authorization Request Endpoint].
///
/// Note that there is no request type because it is by definition the same as
/// [`AuthorizationRequest`].
///
/// [Pushed Authorization Request Endpoint]: https://datatracker.ietf.org/doc/html/rfc9126
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PushedAuthorizationResponse {
    /// The `request_uri` to use for the request to the authorization endpoint.
    pub request_uri: String,

    /// The duration for which the request URI is valid.
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: Duration,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{scope::OPENID, test_utils::assert_serde_json};

    #[test]
    fn serde_refresh_token_grant() {
        let expected = json!({
            "grant_type": "refresh_token",
            "refresh_token": "abcd",
            "scope": "openid",
        });

        // TODO: insert multiple scopes and test it. It's a bit tricky to test since
        // HashSet have no guarantees regarding the ordering of items, so right
        // now the output is unstable.
        let scope: Option<Scope> = Some(vec![OPENID].into_iter().collect());

        let req = AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token: "abcd".into(),
            scope,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn serde_authorization_code_grant() {
        let expected = json!({
            "grant_type": "authorization_code",
            "code": "abcd",
            "redirect_uri": "https://example.com/redirect",
        });

        let req = AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: "abcd".into(),
            redirect_uri: Some("https://example.com/redirect".parse().unwrap()),
            code_verifier: None,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn serialize_grant_type() {
        assert_eq!(
            serde_json::to_string(&GrantType::AuthorizationCode).unwrap(),
            "\"authorization_code\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::RefreshToken).unwrap(),
            "\"refresh_token\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::Implicit).unwrap(),
            "\"implicit\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::ClientCredentials).unwrap(),
            "\"client_credentials\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::DeviceCode).unwrap(),
            "\"urn:ietf:params:oauth:grant-type:device_code\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::ClientInitiatedBackchannelAuthentication).unwrap(),
            "\"urn:openid:params:grant-type:ciba\""
        );
    }

    #[test]
    fn deserialize_grant_type() {
        assert_eq!(
            serde_json::from_str::<GrantType>("\"authorization_code\"").unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"refresh_token\"").unwrap(),
            GrantType::RefreshToken
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"implicit\"").unwrap(),
            GrantType::Implicit
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"client_credentials\"").unwrap(),
            GrantType::ClientCredentials
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"password\"").unwrap(),
            GrantType::Password
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"urn:ietf:params:oauth:grant-type:device_code\"")
                .unwrap(),
            GrantType::DeviceCode
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"urn:openid:params:grant-type:ciba\"").unwrap(),
            GrantType::ClientInitiatedBackchannelAuthentication
        );
    }

    #[test]
    fn serialize_response_mode() {
        assert_eq!(
            serde_json::to_string(&ResponseMode::Query).unwrap(),
            "\"query\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseMode::Fragment).unwrap(),
            "\"fragment\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseMode::FormPost).unwrap(),
            "\"form_post\""
        );
    }

    #[test]
    fn deserialize_response_mode() {
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"query\"").unwrap(),
            ResponseMode::Query
        );
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"fragment\"").unwrap(),
            ResponseMode::Fragment
        );
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"form_post\"").unwrap(),
            ResponseMode::FormPost
        );
    }

    #[test]
    fn serialize_display() {
        assert_eq!(serde_json::to_string(&Display::Page).unwrap(), "\"page\"");
        assert_eq!(serde_json::to_string(&Display::Popup).unwrap(), "\"popup\"");
        assert_eq!(serde_json::to_string(&Display::Touch).unwrap(), "\"touch\"");
        assert_eq!(serde_json::to_string(&Display::Wap).unwrap(), "\"wap\"");
    }

    #[test]
    fn deserialize_display() {
        assert_eq!(
            serde_json::from_str::<Display>("\"page\"").unwrap(),
            Display::Page
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"popup\"").unwrap(),
            Display::Popup
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"touch\"").unwrap(),
            Display::Touch
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"wap\"").unwrap(),
            Display::Wap
        );
    }

    #[test]
    fn serialize_prompt() {
        assert_eq!(serde_json::to_string(&Prompt::None).unwrap(), "\"none\"");
        assert_eq!(serde_json::to_string(&Prompt::Login).unwrap(), "\"login\"");
        assert_eq!(
            serde_json::to_string(&Prompt::Consent).unwrap(),
            "\"consent\""
        );
        assert_eq!(
            serde_json::to_string(&Prompt::SelectAccount).unwrap(),
            "\"select_account\""
        );
        assert_eq!(
            serde_json::to_string(&Prompt::Create).unwrap(),
            "\"create\""
        );
    }

    #[test]
    fn deserialize_prompt() {
        assert_eq!(
            serde_json::from_str::<Prompt>("\"none\"").unwrap(),
            Prompt::None
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"login\"").unwrap(),
            Prompt::Login
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"consent\"").unwrap(),
            Prompt::Consent
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"select_account\"").unwrap(),
            Prompt::SelectAccount
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"create\"").unwrap(),
            Prompt::Create
        );
    }
}
