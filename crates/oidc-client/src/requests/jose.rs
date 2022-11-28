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

//! Requests and method related to JSON Object Signing and Encryption.

use std::collections::HashMap;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use mas_http::JsonResponseLayer;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, TimeOptions},
    jwk::PublicJsonWebKeySet,
    jwt::Jwt,
};
use serde_json::Value;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::{IdTokenError, JwksError, JwtVerificationError},
    http_service::HttpService,
    types::IdToken,
};

/// Fetch a JWKS at the given URL.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `jwks_uri` - The URL where the JWKS can be retrieved.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
#[tracing::instrument(skip_all, fields(jwks_uri))]
pub async fn fetch_jwks(
    http_service: &HttpService,
    jwks_uri: &Url,
) -> Result<PublicJsonWebKeySet, JwksError> {
    tracing::debug!("Fetching JWKS...");

    let jwks_request = http::Request::get(jwks_uri.as_str()).body(Bytes::new())?;

    let service = JsonResponseLayer::<PublicJsonWebKeySet>::default().layer(http_service.clone());

    let response = service.ready_oneshot().await?.call(jwks_request).await?;

    Ok(response.into_body())
}

/// The data required to verify a JWT.
#[derive(Clone, Copy)]
pub struct JwtVerificationData<'a> {
    /// The URL of the issuer that generated the ID Token.
    pub issuer: &'a Url,

    /// The issuer's JWKS.
    pub jwks: &'a PublicJsonWebKeySet,

    /// The ID obtained when registering the client.
    pub client_id: &'a String,

    /// The JWA that should have been used to sign the JWT, as set during
    /// client registration.
    pub signing_algorithm: &'a JsonWebSignatureAlg,
}

/// Decode and verify a signed JWT.
///
/// The following checks are performed:
///
/// * The signature is verified with the given JWKS.
///
/// * The `iss` claim must be present and match the issuer.
///
/// * The `aud` claim must be present and match the client ID.
///
/// * The `alg` in the header must match the signing algorithm.
///
/// # Arguments
///
/// * `jwt` - The serialized JWT to decode and verify.
///
/// * `jwks` - The JWKS that should contain the public key to verify the JWT's
///   signature.
///
/// * `issuer` - The issuer of the JWT.
///
/// * `audience` - The audience that the JWT is intended for.
///
/// * `signing_algorithm` - The JWA that should have been used to sign the JWT.
///
/// # Errors
///
/// Returns an error if the data is invalid or verification fails.
pub fn verify_signed_jwt<'a>(
    jwt: &'a str,
    verification_data: JwtVerificationData<'_>,
) -> Result<Jwt<'a, HashMap<String, Value>>, JwtVerificationError> {
    tracing::debug!("Validating JWT...");

    let JwtVerificationData {
        issuer,
        jwks,
        client_id,
        signing_algorithm,
    } = verification_data;

    let jwt: Jwt<HashMap<String, Value>> = jwt.try_into()?;

    jwt.verify_with_jwks(jwks)?;

    let (header, mut claims) = jwt.clone().into_parts();

    // Must have the proper issuer.
    claims::ISS.extract_required_with_options(&mut claims, issuer.as_str())?;

    // Must have the proper audience.
    claims::AUD.extract_required_with_options(&mut claims, client_id)?;

    // Must use the proper algorithm.
    if header.alg() != signing_algorithm {
        return Err(JwtVerificationError::WrongSignatureAlg);
    }

    Ok(jwt)
}

/// Decode and verify an ID Token.
///
/// Besides the checks of [`verify_signed_jwt()`], the following checks are
/// performed:
///
/// * The `exp` claim must be present and the token must not have expired.
///
/// * The `iat` claim must be present must be in the past.
///
/// * The `sub` claim must be present.
///
/// If an authorization ID token is provided, these extra checks are performed:
///
/// * The `sub` claims must match.
///
/// * The `auth_time` claims must match.
///
/// # Arguments
///
/// * `id_token` - The serialized ID Token to decode and verify.
///
/// * `verification_data` - The data necessary to verify the ID Token.
///
/// * `auth_id_token` - If the ID Token is not verified during an authorization
///   request, the ID token that was returned from the latest authorization
///   request.
///
/// # Errors
///
/// Returns an error if the data is invalid or verification fails.
pub fn verify_id_token<'a>(
    id_token: &'a str,
    verification_data: JwtVerificationData<'_>,
    auth_id_token: Option<&IdToken<'_>>,
    now: DateTime<Utc>,
) -> Result<IdToken<'a>, IdTokenError> {
    let id_token = verify_signed_jwt(id_token, verification_data)?;

    let mut claims = id_token.payload().clone();

    let time_options = TimeOptions::new(now);
    // Must not have expired.
    claims::EXP.extract_required_with_options(&mut claims, &time_options)?;

    // `iat` claim must be present.
    claims::IAT.extract_required_with_options(&mut claims, time_options)?;

    // Subject identifier must be present.
    let sub = claims::SUB.extract_required(&mut claims)?;

    // No more checks if there is no previous ID token.
    let auth_id_token = match auth_id_token {
        Some(id_token) => id_token,
        None => return Ok(id_token),
    };

    let mut auth_claims = auth_id_token.payload().clone();

    // Subject identifier must always be the same.
    let auth_sub = claims::SUB.extract_required(&mut auth_claims)?;
    if sub != auth_sub {
        return Err(IdTokenError::WrongSubjectIdentifier);
    }

    // If the authentication time is present, it must be unchanged.
    if let Some(auth_time) = claims::AUTH_TIME.extract_optional(&mut claims)? {
        let prev_auth_time = claims::AUTH_TIME.extract_required(&mut auth_claims)?;

        if prev_auth_time != auth_time {
            return Err(IdTokenError::WrongAuthTime);
        }
    }

    Ok(id_token)
}
