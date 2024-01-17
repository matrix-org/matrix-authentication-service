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

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

use assert_matches::assert_matches;
use chrono::Duration;
use mas_iana::oauth::{
    OAuthAccessTokenType, OAuthClientAuthenticationMethod, PkceCodeChallengeMethod,
};
use mas_jose::{claims::ClaimError, jwk::PublicJsonWebKeySet};
use mas_oidc_client::{
    error::{
        AuthorizationError, IdTokenError, PushedAuthorizationError, TokenAuthorizationCodeError,
    },
    requests::{
        authorization_code::{
            access_token_with_authorization_code, build_authorization_url,
            build_par_authorization_url, AuthorizationRequestData, AuthorizationValidationData,
        },
        jose::JwtVerificationData,
    },
    types::scope::{ScopeExt, ScopeToken},
};
use oauth2_types::requests::{AccessTokenResponse, Display, Prompt, PushedAuthorizationResponse};
use rand::SeedableRng;
use tokio::sync::oneshot;
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{
    client_credentials, id_token, init_test, now, ACCESS_TOKEN, AUTHORIZATION_CODE, CLIENT_ID,
    CODE_VERIFIER, ID_TOKEN_SIGNING_ALG, NONCE, REDIRECT_URI, REQUEST_URI,
};

#[test]
fn pass_authorization_url() {
    let issuer = Url::parse("http://localhost/").unwrap();
    let authorization_endpoint = issuer.join("authorize").unwrap();
    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let (url, validation_data) = build_authorization_url(
        authorization_endpoint,
        AuthorizationRequestData::new(
            CLIENT_ID.to_owned(),
            [ScopeToken::Openid].into_iter().collect(),
            redirect_uri,
        )
        .with_code_challenge_methods_supported(vec![PkceCodeChallengeMethod::S256]),
        &mut rng,
    )
    .unwrap();

    assert_eq!(validation_data.state, "OrJ8xbWovSpJUTKz");
    assert_eq!(
        validation_data.code_challenge_verifier.unwrap(),
        "TSgZ_hr3TJPjhq4aDp34K_8ksjLwaa1xDcPiRGBcjhM"
    );

    assert_eq!(url.path(), "/authorize");

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.get("scope").unwrap(), "openid");
    assert_eq!(query_pairs.get("response_type").unwrap(), "code");
    assert_eq!(query_pairs.get("client_id").unwrap(), CLIENT_ID);
    assert_eq!(query_pairs.get("redirect_uri").unwrap(), REDIRECT_URI);
    assert_eq!(query_pairs.get("display"), None);
    assert_eq!(query_pairs.get("prompt"), None);
    assert_eq!(query_pairs.get("max_age"), None);
    assert_eq!(query_pairs.get("ui_locales"), None);
    assert_eq!(query_pairs.get("id_token_hint"), None);
    assert_eq!(query_pairs.get("login_hint"), None);
    assert_eq!(query_pairs.get("acr_values"), None);
    assert_eq!(*query_pairs.get("state").unwrap(), validation_data.state);
    assert_eq!(query_pairs.get("nonce").unwrap(), "ox0PigY5l9xl5uTL");
    let code_challenge = query_pairs.get("code_challenge").unwrap();
    assert!(code_challenge.len() >= 43);
    assert_eq!(query_pairs.get("code_challenge_method").unwrap(), "S256");
}

#[test]
fn pass_full_authorization_url() {
    let issuer = Url::parse("http://localhost/").unwrap();
    let authorization_endpoint = issuer.join("authorize").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let authorization_data = AuthorizationRequestData::new(
        CLIENT_ID.to_owned(),
        [ScopeToken::Openid].into_iter().collect(),
        Url::parse(REDIRECT_URI).unwrap(),
    )
    .with_display(Display::Touch)
    .with_prompt(vec![Prompt::Create])
    .with_max_age(NonZeroU32::new(86400).unwrap())
    .with_ui_locales(vec!["de".parse().unwrap()])
    .with_id_token_hint("fake.id.token".to_owned())
    .with_login_hint("mxid:@user:localhost".to_owned())
    .with_acr_values(["custom".to_owned()].into());

    let (url, validation_data) =
        build_authorization_url(authorization_endpoint, authorization_data, &mut rng).unwrap();

    assert_eq!(validation_data.state, "OrJ8xbWovSpJUTKz");
    assert_eq!(validation_data.code_challenge_verifier, None);

    assert_eq!(url.path(), "/authorize");

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.get("scope").unwrap(), "openid");
    assert_eq!(query_pairs.get("response_type").unwrap(), "code");
    assert_eq!(query_pairs.get("client_id").unwrap(), CLIENT_ID);
    assert_eq!(query_pairs.get("redirect_uri").unwrap(), REDIRECT_URI);
    assert_eq!(query_pairs.get("display").unwrap(), "touch");
    assert_eq!(query_pairs.get("prompt").unwrap(), "create");
    assert_eq!(query_pairs.get("max_age").unwrap(), "86400");
    assert_eq!(query_pairs.get("ui_locales").unwrap(), "de");
    assert_eq!(query_pairs.get("id_token_hint").unwrap(), "fake.id.token");
    assert_eq!(
        query_pairs.get("login_hint").unwrap(),
        "mxid:@user:localhost"
    );
    assert_eq!(query_pairs.get("acr_values").unwrap(), "custom");
    assert_eq!(*query_pairs.get("state").unwrap(), validation_data.state);
    assert_eq!(query_pairs.get("nonce").unwrap(), "ox0PigY5l9xl5uTL");
    assert_eq!(query_pairs.get("code_challenge"), None);
    assert_eq!(query_pairs.get("code_challenge_method"), None);
}

#[tokio::test]
async fn pass_pushed_authorization_request() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let authorization_endpoint = issuer.join("authorize").unwrap();
    let par_endpoint = issuer.join("par").unwrap();
    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let (sender, receiver) = oneshot::channel();
    let sender_mutex = Arc::new(Mutex::new(Some(sender)));

    Mock::given(method("POST"))
        .and(path("/par"))
        .and(move |req: &Request| {
            let body = form_urlencoded::parse(&req.body)
                .into_owned()
                .collect::<HashMap<_, _>>();
            if let Some(sender) = sender_mutex.lock().unwrap().take() {
                sender.send(body).unwrap();
                true
            } else {
                false
            }
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(PushedAuthorizationResponse {
                request_uri: REQUEST_URI.to_owned(),
                expires_in: Duration::seconds(30),
            }),
        )
        .mount(&mock_server)
        .await;

    let (url, validation_data) = build_par_authorization_url(
        &http_service,
        client_credentials,
        &par_endpoint,
        authorization_endpoint,
        AuthorizationRequestData::new(
            CLIENT_ID.to_owned(),
            [ScopeToken::Openid].into_iter().collect(),
            redirect_uri,
        )
        .with_code_challenge_methods_supported(vec![PkceCodeChallengeMethod::S256]),
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(validation_data.state, "OrJ8xbWovSpJUTKz");
    assert_eq!(
        validation_data.code_challenge_verifier.unwrap(),
        "TSgZ_hr3TJPjhq4aDp34K_8ksjLwaa1xDcPiRGBcjhM"
    );

    let request_pairs = receiver.await.unwrap();

    assert_eq!(url.path(), "/authorize");
    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.get("request_uri").unwrap(), REQUEST_URI,);
    assert_eq!(query_pairs.get("client_id").unwrap(), CLIENT_ID);

    assert_eq!(request_pairs.get("scope").unwrap(), "openid");
    assert_eq!(request_pairs.get("response_type").unwrap(), "code");
    assert_eq!(request_pairs.get("client_id").unwrap(), CLIENT_ID);
    assert_eq!(request_pairs.get("redirect_uri").unwrap(), REDIRECT_URI);
    assert_eq!(*request_pairs.get("state").unwrap(), validation_data.state);
    assert_eq!(request_pairs.get("nonce").unwrap(), "ox0PigY5l9xl5uTL");
    let code_challenge = request_pairs.get("code_challenge").unwrap();
    assert!(code_challenge.len() >= 43);
    assert_eq!(request_pairs.get("code_challenge_method").unwrap(), "S256");
}

#[tokio::test]
async fn fail_pushed_authorization_request_404() {
    let (http_service, _, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let authorization_endpoint = issuer.join("authorize").unwrap();
    let par_endpoint = issuer.join("par").unwrap();
    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let error = build_par_authorization_url(
        &http_service,
        client_credentials,
        &par_endpoint,
        authorization_endpoint,
        AuthorizationRequestData::new(
            CLIENT_ID.to_owned(),
            [ScopeToken::Openid].into_iter().collect(),
            redirect_uri,
        )
        .with_code_challenge_methods_supported(vec![PkceCodeChallengeMethod::S256]),
        now(),
        &mut rng,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        AuthorizationError::PushedAuthorization(PushedAuthorizationError::Http(_))
    );
}

/// Check if the given request to the token endpoint is valid.
fn is_valid_token_endpoint_request(req: &Request) -> bool {
    let body = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

    if body.get("client_id").filter(|s| *s == CLIENT_ID).is_none() {
        println!("Missing or wrong client ID");
        return false;
    }
    if body
        .get("grant_type")
        .filter(|s| *s == "authorization_code")
        .is_none()
    {
        println!("Missing or wrong grant type");
        return false;
    }
    if body
        .get("code")
        .filter(|s| *s == AUTHORIZATION_CODE)
        .is_none()
    {
        println!("Missing or wrong authorization code");
        return false;
    }
    if body
        .get("redirect_uri")
        .filter(|s| *s == REDIRECT_URI)
        .is_none()
    {
        println!("Missing or wrong redirect URI");
        return false;
    }

    if body
        .get("code_verifier")
        .filter(|s| *s == CODE_VERIFIER)
        .is_none()
    {
        println!("Missing or wrong code verifier");
        return false;
    }

    true
}

#[tokio::test]
async fn pass_access_token_with_authorization_code() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let validation_data = AuthorizationValidationData {
        state: "some_state".to_owned(),
        nonce: NONCE.to_owned(),
        redirect_uri,
        code_challenge_verifier: Some(CODE_VERIFIER.to_owned()),
    };

    let (id_token, jwks) = id_token(issuer.as_str());
    let id_token_verification_data = JwtVerificationData {
        issuer: issuer.as_str(),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(is_valid_token_endpoint_request)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: Some(id_token.to_string()),
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: Some([ScopeToken::Openid].into_iter().collect()),
            }),
        )
        .mount(&mock_server)
        .await;

    let (response, response_id_token) = access_token_with_authorization_code(
        &http_service,
        client_credentials,
        &token_endpoint,
        AUTHORIZATION_CODE.to_owned(),
        validation_data,
        Some(id_token_verification_data),
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(response.access_token, ACCESS_TOKEN);
    assert_eq!(response.refresh_token, None);
    assert!(response.scope.unwrap().contains_token(&ScopeToken::Openid));
    assert_eq!(response_id_token.unwrap().as_str(), id_token.as_str());
}

#[tokio::test]
async fn fail_access_token_with_authorization_code_wrong_nonce() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let validation_data = AuthorizationValidationData {
        state: "some_state".to_owned(),
        nonce: "wrong_nonce".to_owned(),
        redirect_uri,
        code_challenge_verifier: Some(CODE_VERIFIER.to_owned()),
    };

    let (id_token, jwks) = id_token(issuer.as_str());
    let id_token_verification_data = JwtVerificationData {
        issuer: issuer.as_str(),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(is_valid_token_endpoint_request)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: Some(id_token.into_string()),
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: Some([ScopeToken::Openid].into_iter().collect()),
            }),
        )
        .mount(&mock_server)
        .await;

    let error = access_token_with_authorization_code(
        &http_service,
        client_credentials,
        &token_endpoint,
        AUTHORIZATION_CODE.to_owned(),
        validation_data,
        Some(id_token_verification_data),
        now(),
        &mut rng,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        TokenAuthorizationCodeError::IdToken(IdTokenError::Claim(ClaimError::ValidationError {
            claim: "nonce",
            ..
        }))
    );
}

#[tokio::test]
async fn fail_access_token_with_authorization_code_no_id_token() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let redirect_uri = Url::parse(REDIRECT_URI).unwrap();
    let nonce = "some_nonce".to_owned();
    let validation_data = AuthorizationValidationData {
        state: "some_state".to_owned(),
        nonce: nonce.clone(),
        redirect_uri,
        code_challenge_verifier: Some(CODE_VERIFIER.to_owned()),
    };

    let id_token_verification_data = JwtVerificationData {
        issuer: issuer.as_str(),
        jwks: &PublicJsonWebKeySet::default(),
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(is_valid_token_endpoint_request)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: Some([ScopeToken::Openid].into_iter().collect()),
            }),
        )
        .mount(&mock_server)
        .await;

    let error = access_token_with_authorization_code(
        &http_service,
        client_credentials,
        &token_endpoint,
        AUTHORIZATION_CODE.to_owned(),
        validation_data,
        Some(id_token_verification_data),
        now(),
        &mut rng,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        TokenAuthorizationCodeError::IdToken(IdTokenError::MissingIdToken)
    );
}
