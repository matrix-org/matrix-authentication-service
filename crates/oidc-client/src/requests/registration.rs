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

//! Requests for [Dynamic Registration].
//!
//! [Dynamic Registration]: https://openid.net/specs/openid-connect-registration-1_0.html

use mas_http::{CatchHttpCodesLayer, JsonRequestLayer, JsonResponseLayer};
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use oauth2_types::registration::{ClientRegistrationResponse, VerifiedClientMetadata};
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::RegistrationError,
    http_service::HttpService,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Register a client with an OpenID Provider.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `registration_endpoint` - The URL of the issuer's Registration endpoint.
///
/// * `client_metadata` - The metadata to register with the issuer.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(registration_endpoint))]
pub async fn register_client(
    http_service: &HttpService,
    registration_endpoint: &Url,
    client_metadata: VerifiedClientMetadata,
) -> Result<ClientRegistrationResponse, RegistrationError> {
    tracing::debug!("Registering client...");

    let registration_req =
        http::Request::post(registration_endpoint.as_str()).body(client_metadata.clone())?;

    let service = (
        JsonRequestLayer::default(),
        JsonResponseLayer::<ClientRegistrationResponse>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let response = service
        .ready_oneshot()
        .await?
        .call(registration_req)
        .await?
        .into_body();

    match client_metadata.token_endpoint_auth_method() {
        OAuthClientAuthenticationMethod::ClientSecretPost
        | OAuthClientAuthenticationMethod::ClientSecretBasic
        | OAuthClientAuthenticationMethod::ClientSecretJwt => {
            response
                .client_secret
                .as_ref()
                .ok_or(RegistrationError::MissingClientSecret)?;
        }
        _ => {}
    }

    Ok(response)
}
