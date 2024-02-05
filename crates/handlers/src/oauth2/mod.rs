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

use std::collections::HashMap;

use chrono::Duration;
use mas_data_model::{
    AccessToken, Authentication, AuthorizationGrant, BrowserSession, Client, RefreshToken, Session,
    TokenType,
};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, hash_token},
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
use mas_storage::{Clock, RepositoryAccess};
use thiserror::Error;

pub mod authorization;
pub mod consent;
pub mod device;
pub mod discovery;
pub mod introspection;
pub mod keys;
pub mod registration;
pub mod revoke;
pub mod token;
pub mod userinfo;
pub mod webfinger;

#[derive(Debug, Error)]
#[error(transparent)]
pub(crate) enum IdTokenSignatureError {
    #[error("The signing key is invalid")]
    InvalidSigningKey,
    Claim(#[from] mas_jose::claims::ClaimError),
    JwtSignature(#[from] mas_jose::jwt::JwtSignatureError),
    WrongAlgorithm(#[from] mas_keystore::WrongAlgorithmError),
    TokenHash(#[from] mas_jose::claims::TokenHashError),
}

pub(crate) fn generate_id_token(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    clock: &impl Clock,
    url_builder: &UrlBuilder,
    key_store: &Keystore,
    client: &Client,
    grant: Option<&AuthorizationGrant>,
    browser_session: &BrowserSession,
    access_token: Option<&AccessToken>,
    last_authentication: Option<&Authentication>,
) -> Result<String, IdTokenSignatureError> {
    let mut claims = HashMap::new();
    let now = clock.now();
    claims::ISS.insert(&mut claims, url_builder.oidc_issuer().to_string())?;
    claims::SUB.insert(&mut claims, &browser_session.user.sub)?;
    claims::AUD.insert(&mut claims, client.client_id.clone())?;
    claims::IAT.insert(&mut claims, now)?;
    claims::EXP.insert(&mut claims, now + Duration::hours(1))?;

    if let Some(nonce) = grant.and_then(|grant| grant.nonce.as_ref()) {
        claims::NONCE.insert(&mut claims, nonce)?;
    }

    if let Some(last_authentication) = last_authentication {
        claims::AUTH_TIME.insert(&mut claims, last_authentication.created_at)?;
    }

    let alg = client
        .id_token_signed_response_alg
        .clone()
        .unwrap_or(JsonWebSignatureAlg::Rs256);
    let key = key_store
        .signing_key_for_algorithm(&alg)
        .ok_or(IdTokenSignatureError::InvalidSigningKey)?;

    if let Some(access_token) = access_token {
        claims::AT_HASH.insert(&mut claims, hash_token(&alg, &access_token.access_token)?)?;
    }

    if let Some(code) = grant.and_then(|grant| grant.code.as_ref()) {
        claims::C_HASH.insert(&mut claims, hash_token(&alg, &code.code)?)?;
    }

    let signer = key.params().signing_key_for_alg(&alg)?;
    let header = JsonWebSignatureHeader::new(alg)
        .with_kid(key.kid().ok_or(IdTokenSignatureError::InvalidSigningKey)?);
    let id_token = Jwt::sign_with_rng(rng, header, claims, &signer)?;

    Ok(id_token.into_string())
}

pub(crate) async fn generate_token_pair<R: RepositoryAccess>(
    rng: &mut (impl rand::RngCore + Send),
    clock: &impl Clock,
    repo: &mut R,
    session: &Session,
    ttl: Duration,
) -> Result<(AccessToken, RefreshToken), R::Error> {
    let access_token_str = TokenType::AccessToken.generate(rng);
    let refresh_token_str = TokenType::RefreshToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, session, access_token_str, Some(ttl))
        .await?;

    let refresh_token = repo
        .oauth2_refresh_token()
        .add(rng, clock, session, &access_token, refresh_token_str)
        .await?;

    Ok((access_token, refresh_token))
}
