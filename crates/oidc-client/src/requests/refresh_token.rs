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

//! Requests for using [Refresh Tokens].
//!
//! [Refresh Tokens]: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens

use chrono::{DateTime, Utc};
use mas_jose::claims::{self, TokenHash};
use oauth2_types::{
    requests::{AccessTokenRequest, AccessTokenResponse, RefreshTokenGrant},
    scope::Scope,
};
use rand::Rng;
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{IdTokenError, TokenRefreshError},
    http_service::HttpService,
    requests::{jose::verify_id_token, token::request_access_token},
    types::{client_credentials::ClientCredentials, IdToken},
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
/// * `refresh_token` - The token used to refresh the access token returned at
///   the Token endpoint.
///
/// * `scope` - The scope of the access token. The requested scope must not
///   include any scope not originally granted to the access token, and if
///   omitted is treated as equal to the scope originally granted by the issuer.
///
/// * `id_token_verification_data` - The data required to verify the ID Token in
///   the response.
///
///   The signing algorithm corresponds to the `id_token_signed_response_alg`
/// field in the client metadata.
///
///   If it is not provided, the ID Token won't be verified.
///
/// * `auth_id_token` - If an ID Token is expected in the response, the ID token
///   that was returned from the latest authorization request.
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
pub async fn refresh_access_token(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    refresh_token: String,
    scope: Option<Scope>,
    id_token_verification_data: Option<JwtVerificationData<'_>>,
    auth_id_token: Option<&IdToken<'_>>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(AccessTokenResponse, Option<IdToken<'static>>), TokenRefreshError> {
    tracing::debug!("Refreshing access token…");

    let token_response = request_access_token(
        http_service,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token,
            scope,
        }),
        now,
        rng,
    )
    .await?;

    let id_token = if let Some((verification_data, id_token)) =
        id_token_verification_data.zip(token_response.id_token.as_ref())
    {
        let auth_id_token = auth_id_token.ok_or(IdTokenError::MissingAuthIdToken)?;
        let signing_alg = verification_data.signing_algorithm;

        let id_token = verify_id_token(id_token, verification_data, Some(auth_id_token), now)?;

        let mut claims = id_token.payload().clone();

        // Access token hash must match.
        claims::AT_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(signing_alg, &token_response.access_token),
            )
            .map_err(IdTokenError::from)?;

        Some(id_token.into_owned())
    } else {
        None
    };

    Ok((token_response, id_token))
}
