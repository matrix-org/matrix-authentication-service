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

//! Requests for obtaining [Claims] about an end-user.
//!
//! [Claims]: https://openid.net/specs/openid-connect-core-1_0.html#Claims

use std::collections::HashMap;

use bytes::Bytes;
use headers::{Authorization, HeaderMapExt, HeaderValue};
use http::header::{ACCEPT, CONTENT_TYPE};
use mas_http::CatchHttpCodesLayer;
use mas_jose::claims;
use mime::Mime;
use serde_json::Value;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{IdTokenError, UserInfoError},
    http_service::HttpService,
    requests::jose::verify_signed_jwt,
    types::IdToken,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Obtain information about an authenticated end-user.
///
/// Returns a map of claims with their value, that should be extracted with
/// one of the [`Claim`] methods.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `userinfo_endpoint` - The URL of the issuer's User Info endpoint.
///
/// * `access_token` - The access token of the end-user.
///
/// * `jwt_verification_data` - The data required to verify the response if a
///   signed response was requested during client registration.
///
///   The signing algorithm corresponds to the `userinfo_signed_response_alg`
///   field in the client metadata.
///
/// * `auth_id_token` - The ID token that was returned from the latest
///   authorization request.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// validation of the signed response fails.
///
/// [`Claim`]: mas_jose::claims::Claim
#[tracing::instrument(skip_all, fields(userinfo_endpoint))]
pub async fn fetch_userinfo(
    http_service: &HttpService,
    userinfo_endpoint: &Url,
    access_token: &str,
    jwt_verification_data: Option<JwtVerificationData<'_>>,
    auth_id_token: &IdToken<'_>,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Obtaining user info…");

    let mut userinfo_request = http::Request::get(userinfo_endpoint.as_str());

    let expected_content_type = if jwt_verification_data.is_some() {
        "application/jwt"
    } else {
        mime::APPLICATION_JSON.as_ref()
    };

    if let Some(headers) = userinfo_request.headers_mut() {
        headers.typed_insert(Authorization::bearer(access_token)?);
        headers.insert(ACCEPT, HeaderValue::from_static(expected_content_type));
    }

    let userinfo_request = userinfo_request.body(Bytes::new())?;

    let service = CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper)
        .layer(http_service.clone());

    let userinfo_response = service
        .ready_oneshot()
        .await?
        .call(userinfo_request)
        .await?;

    let content_type: Mime = userinfo_response
        .headers()
        .get(CONTENT_TYPE)
        .ok_or(UserInfoError::MissingResponseContentType)?
        .to_str()?
        .parse()?;

    if content_type.essence_str() != expected_content_type {
        return Err(UserInfoError::UnexpectedResponseContentType {
            expected: expected_content_type.to_owned(),
            got: content_type.to_string(),
        });
    }

    let response_body = std::str::from_utf8(userinfo_response.body())?;

    let mut claims = if let Some(verification_data) = jwt_verification_data {
        verify_signed_jwt(response_body, verification_data)
            .map_err(IdTokenError::from)?
            .into_parts()
            .1
    } else {
        serde_json::from_str(response_body)?
    };

    let mut auth_claims = auth_id_token.payload().clone();

    // Subject identifier must always be the same.
    let sub = claims::SUB
        .extract_required(&mut claims)
        .map_err(IdTokenError::from)?;
    let auth_sub = claims::SUB
        .extract_required(&mut auth_claims)
        .map_err(IdTokenError::from)?;
    if sub != auth_sub {
        return Err(IdTokenError::WrongSubjectIdentifier.into());
    }

    Ok(claims)
}
