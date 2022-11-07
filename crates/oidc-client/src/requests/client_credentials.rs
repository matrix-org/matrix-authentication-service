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

//! Requests for the [Client Credentials flow].
//!
//! [Client Credentials flow]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4

use chrono::{DateTime, Utc};
use oauth2_types::{
    requests::{AccessTokenRequest, AccessTokenResponse, ClientCredentialsGrant},
    scope::Scope,
};
use rand::Rng;
use url::Url;

use crate::{
    error::TokenRequestError, http_service::HttpService, requests::token::request_access_token,
    types::client_credentials::ClientCredentials,
};

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
/// * `scope` - The scope to authorize.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(token_endpoint))]
pub async fn access_token_with_client_credentials(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    scope: Option<Scope>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<AccessTokenResponse, TokenRequestError> {
    tracing::debug!("Requesting access token with client credentials...");

    request_access_token(
        http_service,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::ClientCredentials(ClientCredentialsGrant { scope }),
        now,
        rng,
    )
    .await
}
