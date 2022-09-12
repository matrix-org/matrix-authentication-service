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

use std::borrow::Cow;

use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// A client error returned by an authorization server.
///
/// To construct this with a default description for the error code, use its
/// `From<ClientErrorCode>` implementation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientError {
    /// The error code.
    pub error: ClientErrorCode,

    /// A human-readable description of the error.
    pub error_description: Cow<'static, str>,
}

impl ClientError {
    /// Creates a new `ClientError` with the given error code and description.
    #[must_use]
    pub const fn new(error: ClientErrorCode, error_description: &'static str) -> Self {
        Self {
            error,
            error_description: Cow::Borrowed(error_description),
        }
    }

    /// Changes the description of this `ClientError` with the given `String`.
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.error_description = Cow::Owned(description);
        self
    }
}

impl From<ClientErrorCode> for ClientError {
    fn from(error: ClientErrorCode) -> Self {
        let desc = error.default_description();
        Self::new(error, desc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Display, FromStr, SerializeDisplay, DeserializeFromStr)]
#[display(style = "snake_case")]
pub enum ClientErrorCode {
    /// `invalid_request`
    ///
    /// The request is missing a required parameter, includes an invalid
    /// parameter value, includes a parameter more than once, or is otherwise
    /// malformed.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidRequest,

    /// `invalid_client`
    ///
    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method).
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidClient,

    /// `invalid_grant`
    ///
    /// The provided authorization grant (e.g., authorization code, resource
    /// owner credentials) or refresh token is invalid, expired, revoked, does
    /// not match the redirection URI used in the authorization request, or was
    /// issued to another client.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidGrant,

    /// `unauthorized_client`
    ///
    /// The authenticated client is not authorized to use this authorization
    /// grant type.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    UnauthorizedClient,

    /// `unsupported_grant_type`
    ///
    /// The authorization grant type is not supported by the authorization
    /// server.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    UnsupportedGrantType,

    /// `access_denied`
    ///
    /// The resource owner or authorization server denied the request.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    AccessDenied,

    /// `unsupported_response_type`
    ///
    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    UnsupportedResponseType,

    /// `invalid_scope`
    ///
    /// The requested scope is invalid, unknown, malformed, or exceeds the scope
    /// granted by the resource owner.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    InvalidScope,

    /// `server_error`
    ///
    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    ServerError,

    /// `temporarily_unavailable`
    ///
    /// The authorization server is currently unable to handle the request due
    /// to a temporary overloading or maintenance of the server.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    TemporarilyUnavailable,

    /// `interaction_required`
    ///
    /// The authorization server requires end-user interaction of some form to
    /// proceed.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InteractionRequired,

    /// `login_required`
    ///
    /// The authorization server requires end-user authentication.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    LoginRequired,

    /// `account_selection_required`
    ///
    /// The end-user is required to select a session at the authorization
    /// server.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    AccountSelectionRequired,

    /// `consent_required`
    ///
    /// The authorization server requires end-user consent.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    ConsentRequired,

    /// `invalid_request_uri`
    ///
    /// The `request_uri` in the authorization request returns an error or
    /// contains invalid data.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InvalidRequestUri,

    /// `invalid_request_object`
    ///
    /// The request parameter contains an invalid request object.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InvalidRequestObject,

    /// `request_not_supported`
    ///
    /// The authorization server does not support use of the `request`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RequestNotSupported,

    /// `request_uri_not_supported`
    ///
    /// The authorization server does not support use of the `request_uri`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RequestUriNotSupported,

    /// `registration_not_supported`
    ///
    /// The authorization server does not support use of the `registration`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RegistrationNotSupported,

    /// `invalid_redirect_uri`
    ///
    /// The value of one or more redirection URIs is invalid.
    ///
    /// From [RFC7591](https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2).
    InvalidRedirectUri,

    /// `invalid_client_metadata`
    ///
    /// The value of one of the client metadata fields is invalid and the server
    /// has rejected this request.
    ///
    /// From [RFC7591](https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2).
    InvalidClientMetadata,

    /// Another error code.
    #[display("{0}")]
    Unknown(String),
}

impl ClientErrorCode {
    /// Get the default description for this `ClientErrorCode`.
    ///
    /// Note that [`ClientErrorCode::Unknown`] returns an empty string.
    #[must_use]
    pub fn default_description(&self) -> &'static str {
        match self {
            ClientErrorCode::InvalidRequest => {
                "The request is missing a required parameter, includes an \
                invalid parameter value, includes a parameter more than once, \
                or is otherwise malformed."
            }
            ClientErrorCode::InvalidClient => "Client authentication failed.",
            ClientErrorCode::InvalidGrant => {
                "The provided access grant is invalid, expired, or revoked."
            }
            ClientErrorCode::UnauthorizedClient => {
                "The client is not authorized to request an access token using this method."
            }
            ClientErrorCode::UnsupportedGrantType => {
                "The authorization grant type is not supported by the authorization server."
            }
            ClientErrorCode::AccessDenied => {
                "The resource owner or authorization server denied the request."
            }
            ClientErrorCode::UnsupportedResponseType => {
                "The authorization server does not support obtaining an access \
                token using this method."
            }
            ClientErrorCode::InvalidScope => {
                "The requested scope is invalid, unknown, or malformed."
            }
            ClientErrorCode::ServerError => {
                "The authorization server encountered an unexpected condition \
                that prevented it from fulfilling the request."
            }
            ClientErrorCode::TemporarilyUnavailable => {
                "The authorization server is currently unable to handle the request \
                due to a temporary overloading or maintenance of the server."
            }
            ClientErrorCode::InteractionRequired => {
                "The Authorization Server requires End-User interaction of some form to proceed."
            }
            ClientErrorCode::LoginRequired => {
                "The Authorization Server requires End-User authentication."
            }
            ClientErrorCode::AccountSelectionRequired => {
                "The End-User is required to select a session at the Authorization Server."
            }
            ClientErrorCode::ConsentRequired => {
                "The Authorization Server requires End-User consent."
            }
            ClientErrorCode::InvalidRequestUri => {
                "The request_uri in the Authorization Request returns an error \
                or contains invalid data."
            }
            ClientErrorCode::InvalidRequestObject => {
                "The request parameter contains an invalid Request Object."
            }
            ClientErrorCode::RequestNotSupported => {
                "The provider does not support use of the request parameter."
            }
            ClientErrorCode::RequestUriNotSupported => {
                "The provider does not support use of the request_uri parameter."
            }
            ClientErrorCode::RegistrationNotSupported => {
                "The provider does not support use of the registration parameter."
            }
            ClientErrorCode::InvalidRedirectUri => {
                "The value of one or more redirection URIs is invalid."
            }
            ClientErrorCode::InvalidClientMetadata => {
                "The value of one of the client metadata fields is invalid"
            }
            ClientErrorCode::Unknown(_) => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_client_error_code() {
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequest).unwrap(),
            "\"invalid_request\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidClient).unwrap(),
            "\"invalid_client\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidGrant).unwrap(),
            "\"invalid_grant\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnauthorizedClient).unwrap(),
            "\"unauthorized_client\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnsupportedGrantType).unwrap(),
            "\"unsupported_grant_type\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::AccessDenied).unwrap(),
            "\"access_denied\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnsupportedResponseType).unwrap(),
            "\"unsupported_response_type\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidScope).unwrap(),
            "\"invalid_scope\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::ServerError).unwrap(),
            "\"server_error\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::TemporarilyUnavailable).unwrap(),
            "\"temporarily_unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InteractionRequired).unwrap(),
            "\"interaction_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::LoginRequired).unwrap(),
            "\"login_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::AccountSelectionRequired).unwrap(),
            "\"account_selection_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::ConsentRequired).unwrap(),
            "\"consent_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequestUri).unwrap(),
            "\"invalid_request_uri\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequestObject).unwrap(),
            "\"invalid_request_object\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RequestNotSupported).unwrap(),
            "\"request_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RequestUriNotSupported).unwrap(),
            "\"request_uri_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RegistrationNotSupported).unwrap(),
            "\"registration_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRedirectUri).unwrap(),
            "\"invalid_redirect_uri\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidClientMetadata).unwrap(),
            "\"invalid_client_metadata\""
        );

        assert_eq!(
            serde_json::to_string(&ClientErrorCode::Unknown("unknown_error_code".to_owned()))
                .unwrap(),
            "\"unknown_error_code\""
        );
    }

    #[test]
    fn deserialize_client_error_code() {
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request\"").unwrap(),
            ClientErrorCode::InvalidRequest
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_client\"").unwrap(),
            ClientErrorCode::InvalidClient
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_grant\"").unwrap(),
            ClientErrorCode::InvalidGrant
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unauthorized_client\"").unwrap(),
            ClientErrorCode::UnauthorizedClient
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unsupported_grant_type\"").unwrap(),
            ClientErrorCode::UnsupportedGrantType
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"access_denied\"").unwrap(),
            ClientErrorCode::AccessDenied
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unsupported_response_type\"").unwrap(),
            ClientErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_scope\"").unwrap(),
            ClientErrorCode::InvalidScope
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"server_error\"").unwrap(),
            ClientErrorCode::ServerError
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"temporarily_unavailable\"").unwrap(),
            ClientErrorCode::TemporarilyUnavailable
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"interaction_required\"").unwrap(),
            ClientErrorCode::InteractionRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"login_required\"").unwrap(),
            ClientErrorCode::LoginRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"account_selection_required\"").unwrap(),
            ClientErrorCode::AccountSelectionRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"consent_required\"").unwrap(),
            ClientErrorCode::ConsentRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request_uri\"").unwrap(),
            ClientErrorCode::InvalidRequestUri
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request_object\"").unwrap(),
            ClientErrorCode::InvalidRequestObject
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"request_not_supported\"").unwrap(),
            ClientErrorCode::RequestNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"request_uri_not_supported\"").unwrap(),
            ClientErrorCode::RequestUriNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"registration_not_supported\"").unwrap(),
            ClientErrorCode::RegistrationNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_redirect_uri\"").unwrap(),
            ClientErrorCode::InvalidRedirectUri
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_client_metadata\"").unwrap(),
            ClientErrorCode::InvalidClientMetadata
        );

        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unknown_error_code\"").unwrap(),
            ClientErrorCode::Unknown("unknown_error_code".to_owned())
        );
    }
}
