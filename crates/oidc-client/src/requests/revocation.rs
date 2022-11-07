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

//! Requests for [Token Revocation].
//!
//! [Token Revocation]: https://www.rfc-editor.org/rfc/rfc7009.html

use chrono::{DateTime, Utc};
use mas_http::{CatchHttpCodesLayer, FormUrlencodedRequestLayer};
use mas_iana::oauth::OAuthTokenTypeHint;
use oauth2_types::requests::IntrospectionRequest;
use rand::Rng;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::TokenRevokeError,
    http_service::HttpService,
    types::client_credentials::ClientCredentials,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Revoke a token.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `revocation_endpoint` - The URL of the issuer's Revocation endpoint.
///
/// * `token` - The token to revoke.
///
/// * `token_type_hint` - Hint about the type of the token.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(revocation_endpoint))]
pub async fn revoke_token(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    revocation_endpoint: &Url,
    token: String,
    token_type_hint: Option<OAuthTokenTypeHint>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(), TokenRevokeError> {
    tracing::debug!("Revoking token…");

    let request = IntrospectionRequest {
        token,
        token_type_hint,
    };

    let revocation_request = http::Request::post(revocation_endpoint.as_str()).body(request)?;

    let revocation_request = client_credentials.apply_to_request(revocation_request, now, rng)?;

    let service = (
        FormUrlencodedRequestLayer::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    service
        .ready_oneshot()
        .await?
        .call(revocation_request)
        .await?;

    Ok(())
}
