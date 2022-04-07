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

#[derive(serde::Serialize)]
pub struct ClientError {
    pub error: &'static str,
    pub error_description: &'static str,
}

impl ClientError {
    #[must_use]
    pub const fn new(error: &'static str, error_description: &'static str) -> Self {
        Self {
            error,
            error_description,
        }
    }
}

pub mod rfc6749 {
    use super::ClientError;

    pub const INVALID_REQUEST: ClientError = ClientError::new(
        "invalid_request",
        "The request is missing a required parameter, \
         includes an invalid parameter value, \
         includes a parameter more than once, \
         or is otherwise malformed.",
    );

    pub const INVALID_CLIENT: ClientError =
        ClientError::new("invalid_client", "Client authentication failed.");

    pub const INVALID_GRANT: ClientError = ClientError::new(
        "invalid_grant",
        "The provided access grant is invalid, expired, or revoked.",
    );

    pub const UNAUTHORIZED_CLIENT: ClientError = ClientError::new(
        "unauthorized_client",
        "The client is not authorized to request an access token using this method.",
    );

    pub const UNSUPPORTED_GRANT_TYPE: ClientError = ClientError::new(
        "unsupported_grant_type",
        "The authorization grant type is not supported by the authorization server.",
    );

    pub const ACCESS_DENIED: ClientError = ClientError::new(
        "access_denied",
        "The resource owner or authorization server denied the request.",
    );

    pub const UNSUPPORTED_RESPONSE_TYPE: ClientError = ClientError::new(
        "unsupported_response_type",
        "The authorization server does not support obtaining an access token using this method.",
    );

    pub const INVALID_SCOPE: ClientError = ClientError::new(
        "invalid_scope",
        "The requested scope is invalid, unknown, or malformed.",
    );

    pub const SERVER_ERROR: ClientError = ClientError::new(
        "server_error",
        "The authorization server encountered an unexpected condition \
         that prevented it from fulfilling the request.",
    );

    pub const TEMPORARILY_UNAVAILABLE: ClientError = ClientError::new(
        "temporarily_unavailable",
        "The authorization server is currently unable to handle the request \
        due to a temporary overloading or maintenance of the server.",
    );
}

pub mod oidc_core {
    use super::ClientError;

    pub const INTERACTION_REQUIRED: ClientError = ClientError::new(
        "interaction_required",
        "The Authorization Server requires End-User interaction of some form to proceed.",
    );

    pub const LOGIN_REQUIRED: ClientError = ClientError::new(
        "login_required",
        "The Authorization Server requires End-User authentication.",
    );

    pub const ACCOUNT_SELECTION_REQUIRED: ClientError = ClientError::new(
        "account_selection_required",
        "The End-User is REQUIRED to select a session at the Authorization Server.",
    );

    pub const CONSENT_REQUIRED: ClientError = ClientError::new(
        "consent_required",
        "The Authorization Server requires End-User consent.",
    );

    pub const INVALID_REQUEST_URI: ClientError = ClientError::new(
        "invalid_request_uri",
        "The request_uri in the Authorization Request returns an error or contains invalid data. ",
    );

    pub const INVALID_REQUEST_OBJECT: ClientError = ClientError::new(
        "invalid_request_object",
        "The request parameter contains an invalid Request Object.",
    );

    pub const REQUEST_NOT_SUPPORTED: ClientError = ClientError::new(
        "request_not_supported",
        "The provider does not support use of the request parameter.",
    );

    pub const REQUEST_URI_NOT_SUPPORTED: ClientError = ClientError::new(
        "request_uri_not_supported",
        "The provider does not support use of the request_uri parameter.",
    );

    pub const REGISTRATION_NOT_SUPPORTED: ClientError = ClientError::new(
        "registration_not_supported",
        "The provider does not support use of the registration parameter.",
    );
}

pub use oidc_core::*;
pub use rfc6749::*;
