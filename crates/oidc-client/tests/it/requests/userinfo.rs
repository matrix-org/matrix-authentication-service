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

use assert_matches::assert_matches;
use mas_oidc_client::{
    error::{IdTokenError, UserInfoError},
    requests::userinfo::fetch_userinfo,
};
use serde_json::json;
use wiremock::{
    matchers::{header, method, path},
    Mock, ResponseTemplate,
};

use crate::{id_token, init_test, ACCESS_TOKEN, SUBJECT_IDENTIFIER};

#[tokio::test]
async fn pass_fetch_userinfo() {
    let (http_service, mock_server, issuer) = init_test().await;
    let userinfo_endpoint = issuer.join("userinfo").unwrap();
    let (auth_id_token, _) = id_token(&issuer);

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header(
            "authorization",
            format!("Bearer {ACCESS_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": SUBJECT_IDENTIFIER,
            "email": "janedoe@example.com",
        })))
        .mount(&mock_server)
        .await;

    let claims = fetch_userinfo(
        &http_service,
        &userinfo_endpoint,
        ACCESS_TOKEN,
        None,
        &auth_id_token,
    )
    .await
    .unwrap();

    assert_eq!(claims.get("email").unwrap(), "janedoe@example.com");
}

#[tokio::test]
async fn fail_wrong_subject_identifier() {
    let (http_service, mock_server, issuer) = init_test().await;
    let userinfo_endpoint = issuer.join("userinfo").unwrap();
    let (auth_id_token, _) = id_token(&issuer);

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header(
            "authorization",
            format!("Bearer {ACCESS_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "wrong_subject_identifier",
            "email": "janedoe@example.com",
        })))
        .mount(&mock_server)
        .await;

    let error = fetch_userinfo(
        &http_service,
        &userinfo_endpoint,
        ACCESS_TOKEN,
        None,
        &auth_id_token,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        UserInfoError::IdToken(IdTokenError::WrongSubjectIdentifier)
    );
}
