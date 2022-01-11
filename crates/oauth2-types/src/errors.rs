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

use http::status::StatusCode;
use serde::ser::{Serialize, SerializeMap};
use url::Url;

pub trait OAuth2Error: std::fmt::Debug + Send + Sync {
    /// A single ASCII error code.
    ///
    /// Maps to the required "error" field.
    fn error(&self) -> &'static str;

    /// Human-readable ASCII text providing additional information, used to
    /// assist the client developer in understanding the error that
    /// occurred.
    ///
    /// Maps to the optional `error_description` field.
    fn description(&self) -> Option<String> {
        None
    }

    /// A URI identifying a human-readable web page with information about the
    /// error, used to provide the client developer with additional
    /// information about the error.
    ///
    /// Maps to the optional `error_uri` field.
    fn uri(&self) -> Option<Url> {
        None
    }

    /// Wraps the error with an `ErrorResponse` to help serializing.
    fn into_response(self) -> ErrorResponse
    where
        Self: Sized + 'static,
    {
        ErrorResponse(Box::new(self))
    }
}

pub trait OAuth2ErrorCode: OAuth2Error + 'static {
    /// The HTTP status code that must be returned by this error
    fn status(&self) -> StatusCode;
}

impl OAuth2Error for &Box<dyn OAuth2ErrorCode> {
    fn error(&self) -> &'static str {
        self.as_ref().error()
    }
    fn description(&self) -> Option<String> {
        self.as_ref().description()
    }

    fn uri(&self) -> Option<Url> {
        self.as_ref().uri()
    }
}

#[derive(Debug)]
pub struct ErrorResponse(Box<dyn OAuth2Error>);

impl From<Box<dyn OAuth2Error>> for ErrorResponse {
    fn from(b: Box<dyn OAuth2Error>) -> Self {
        Self(b)
    }
}

impl OAuth2Error for ErrorResponse {
    fn error(&self) -> &'static str {
        self.0.error()
    }

    fn description(&self) -> Option<String> {
        self.0.description()
    }

    fn uri(&self) -> Option<Url> {
        self.0.uri()
    }
}

impl Serialize for ErrorResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let error = self.0.error();
        let description = self.0.description();
        let uri = self.0.uri();

        // Count the number of fields to serialize
        let len = {
            let mut x = 1;
            if description.is_some() {
                x += 1;
            }
            if uri.is_some() {
                x += 1;
            }
            x
        };

        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("error", error)?;
        if let Some(ref description) = description {
            map.serialize_entry("error_description", description)?;
        }
        if let Some(ref uri) = uri {
            map.serialize_entry("error_uri", uri)?;
        }
        map.end()
    }
}

macro_rules! oauth2_error_def {
    ($name:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name;
    };
}

macro_rules! oauth2_error_status {
    ($name:ident, $code:ident) => {
        impl $crate::errors::OAuth2ErrorCode for $name {
            fn status(&self) -> ::http::status::StatusCode {
                ::http::status::StatusCode::$code
            }
        }
    };
}

macro_rules! oauth2_error_error {
    ($err:literal) => {
        fn error(&self) -> &'static str {
            $err
        }
    };
}

macro_rules! oauth2_error_description {
    ($description:expr) => {
        fn description(&self) -> Option<String> {
            Some(($description).to_string())
        }
    };
}

macro_rules! oauth2_error {
    ($name:ident, $err:literal => $description:expr) => {
        oauth2_error_def!($name);
        impl $crate::errors::OAuth2Error for $name {
            oauth2_error_error!($err);
            oauth2_error_description!(indoc::indoc! {$description});
        }
    };
    ($name:ident, $err:literal) => {
        oauth2_error_def!($name);
        impl $crate::errors::OAuth2Error for $name {
            oauth2_error_error!($err);
        }
    };
    ($name:ident, code: $code:ident, $err:literal => $description:expr) => {
        oauth2_error!($name, $err => $description);
        oauth2_error_status!($name, $code);
    };
    ($name:ident, code: $code:ident, $err:literal) => {
        oauth2_error!($name, $err);
        oauth2_error_status!($name, $code);
    };
}

pub mod rfc6749 {
    oauth2_error! {
        InvalidRequest,
        code: BAD_REQUEST,
        "invalid_request" =>
        "The request is missing a required parameter, includes an invalid parameter value, \
         includes a parameter more than once, or is otherwise malformed."
    }

    oauth2_error! {
        InvalidClient,
        code: BAD_REQUEST,
        "invalid_client" =>
        "Client authentication failed."
    }

    oauth2_error! {
        InvalidGrant,
        code: BAD_REQUEST,
        "invalid_grant"
    }

    oauth2_error! {
        UnauthorizedClient,
        code: BAD_REQUEST,
        "unauthorized_client" =>
        "The client is not authorized to request an access token using this method."
    }

    oauth2_error! {
        UnsupportedGrantType,
        code: BAD_REQUEST,
        "unsupported_grant_type" =>
        "The authorization grant type is not supported by the authorization server."
    }

    oauth2_error! {
        AccessDenied,
        "access_denied" =>
        "The resource owner or authorization server denied the request."
    }

    oauth2_error! {
        UnsupportedResponseType,
        "unsupported_response_type" =>
        "The authorization server does not support obtaining an access token using this method."
    }

    oauth2_error! {
        InvalidScope,
        code: BAD_REQUEST,
        "invalid_scope" =>
        "The requested scope is invalid, unknown, or malformed."
    }

    oauth2_error! {
        ServerError,
        code: INTERNAL_SERVER_ERROR,
        "server_error" =>
        "The authorization server encountered an unexpected \
         condition that prevented it from fulfilling the request."
    }

    oauth2_error! {
        TemporarilyUnavailable,
        "temporarily_unavailable" =>
        "The authorization server is currently unable to handle \
         the request due to a temporary overloading or maintenance \
         of the server."
    }
}

pub mod oidc_core {
    oauth2_error! {
        InteractionRequired,
        "interaction_required" =>
        "The Authorization Server requires End-User interaction of some form to proceed."
    }

    oauth2_error! {
        LoginRequired,
        "login_required" =>
        "The Authorization Server requires End-User authentication."
    }

    oauth2_error! {
        AccountSelectionRequired,
        "account_selection_required"
    }

    oauth2_error! {
        ConsentRequired,
        "consent_required"
    }

    oauth2_error! {
        InvalidRequestUri,
        "invalid_request_uri" =>
        "The request_uri in the Authorization Request returns an error or contains invalid data. "
    }

    oauth2_error! {
        InvalidRequestObject,
        "invalid_request_object" =>
        "The request parameter contains an invalid Request Object."
    }

    oauth2_error! {
        RequestNotSupported,
        "request_not_supported" =>
        "The provider does not support use of the request parameter."
    }

    oauth2_error! {
        RequestUriNotSupported,
        "request_uri_not_supported" =>
        "The provider does not support use of the request_uri parameter."
    }

    oauth2_error! {
        RegistrationNotSupported,
        "registration_not_supported" =>
        "The provider does not support use of the registration parameter."
    }
}

pub use oidc_core::*;
pub use rfc6749::*;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serialize_error() {
        let expected = json!({"error": "invalid_grant"});
        let actual = serde_json::to_value(InvalidGrant.into_response()).unwrap();
        assert_eq!(expected, actual);
    }
}
