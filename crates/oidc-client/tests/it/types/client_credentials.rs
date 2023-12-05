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

use std::collections::HashMap;

use assert_matches::assert_matches;
use base64ct::Encoding;
use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_jose::{
    claims::{self, TimeOptions},
    jwt::Jwt,
};
use mas_oidc_client::{
    error::{CredentialsError, TokenRequestError},
    requests::client_credentials::access_token_with_client_credentials,
    types::client_credentials::ClientCredentials,
};
use oauth2_types::requests::AccessTokenResponse;
use rand::SeedableRng;
use serde_json::Value;
use tower::BoxError;
use wiremock::{
    matchers::{header, method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{client_credentials, init_test, now, ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET};

#[tokio::test]
async fn pass_none() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_basic() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::ClientSecretBasic,
        &issuer,
        None,
    );
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let username = form_urlencoded::byte_serialize(CLIENT_ID.as_bytes()).collect::<String>();
    let password = form_urlencoded::byte_serialize(CLIENT_SECRET.as_bytes()).collect::<String>();
    let enc_user_pass =
        base64ct::Base64::encode_string(format!("{username}:{password}").as_bytes());
    let authorization_header = format!("Basic {enc_user_pass}");

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", authorization_header.as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_post() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::ClientSecretPost,
        &issuer,
        None,
    );
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }
            if query_pairs
                .get("client_secret")
                .filter(|s| *s == CLIENT_SECRET)
                .is_none()
            {
                println!("Wrong or missing client secret");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_jwt() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::ClientSecretJwt,
        &issuer,
        None,
    );
    let token_endpoint = issuer.join("token").unwrap();
    let endpoint = token_endpoint.to_string();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(move |req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }
            if query_pairs
                .get("client_assertion_type")
                .filter(|s| *s == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .is_none()
            {
                println!("Wrong or missing client assertion type");
                return false;
            }

            let Some(jwt) = query_pairs.get("client_assertion") else {
                println!("Missing client assertion");
                return false;
            };

            let jwt = Jwt::<HashMap<String, Value>>::try_from(jwt.as_ref()).unwrap();
            if jwt
                .verify_with_shared_secret(CLIENT_SECRET.as_bytes().to_owned())
                .is_err()
            {
                println!("Client assertion signature verification failed");
                return false;
            }

            let mut claims = jwt.into_parts().1;
            if let Err(error) = verify_client_jwt(&mut claims, &endpoint) {
                println!("Client assertion claims verification failed: {error}");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_private_key_jwt_with_keystore() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::PrivateKeyJwt,
        &issuer,
        None,
    );
    let token_endpoint = issuer.join("token").unwrap();
    let endpoint = token_endpoint.to_string();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let client_jwks = if let ClientCredentials::PrivateKeyJwt {
        jwt_signing_method, ..
    } = &client_credentials
    {
        let keystore = jwt_signing_method.keystore().unwrap();
        keystore.public_jwks()
    } else {
        panic!("should be PrivateKeyJwt")
    };

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(move |req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }
            if query_pairs
                .get("client_assertion_type")
                .filter(|s| *s == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .is_none()
            {
                println!("Wrong or missing client assertion type");
                return false;
            }

            let Some(jwt) = query_pairs.get("client_assertion") else {
                println!("Missing client assertion");
                return false;
            };

            let jwt = Jwt::<HashMap<String, Value>>::try_from(jwt.as_ref()).unwrap();
            if jwt.verify_with_jwks(&client_jwks).is_err() {
                println!("Client assertion signature verification failed");
                return false;
            }

            let mut claims = jwt.into_parts().1;
            if let Err(error) = verify_client_jwt(&mut claims, &endpoint) {
                println!("Client assertion claims verification failed: {error}");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_private_key_jwt_with_custom_signing() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::PrivateKeyJwt,
        &issuer,
        Some(Box::new(|_claims, _alg| Ok("fake.signed.jwt".to_owned()))),
    );
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(move |req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }
            if query_pairs
                .get("client_assertion_type")
                .filter(|s| *s == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .is_none()
            {
                println!("Wrong or missing client assertion type");
                return false;
            }

            if query_pairs
                .get("client_assertion")
                .filter(|s| *s == "fake.signed.jwt")
                .is_none()
            {
                println!("Wrong or missing client assertion");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn fail_private_key_jwt_with_custom_signing() {
    let (http_service, _, issuer) = init_test().await;
    let client_credentials = client_credentials(
        &OAuthClientAuthenticationMethod::PrivateKeyJwt,
        &issuer,
        Some(Box::new(|_claims, _alg| Err("Something went wrong".into()))),
    );
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let error = access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        TokenRequestError::Credentials(CredentialsError::Custom(_))
    );
}

fn verify_client_jwt(
    claims: &mut HashMap<String, Value>,
    token_endpoint: &String,
) -> Result<(), BoxError> {
    claims::ISS.extract_required_with_options(claims, CLIENT_ID)?;

    let sub = claims::SUB.extract_required(claims)?;
    if sub != CLIENT_ID {
        return Err("Wrong sub".into());
    }

    claims::AUD.extract_required_with_options(claims, token_endpoint)?;

    claims::EXP.extract_required_with_options(claims, TimeOptions::new(now()))?;

    Ok(())
}
