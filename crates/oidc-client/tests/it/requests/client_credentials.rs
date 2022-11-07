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

use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_oidc_client::{
    requests::client_credentials::access_token_with_client_credentials,
    types::scope::{ScopeExt, ScopeToken},
};
use oauth2_types::{requests::AccessTokenResponse, scope::Scope};
use rand::SeedableRng;
use wiremock::{
    matchers::{method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{client_credentials, init_test, now, ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET};

#[tokio::test]
async fn pass_access_token_with_client_credentials() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(
        OAuthClientAuthenticationMethod::ClientSecretPost,
        &issuer,
        None,
    );
    let token_endpoint = issuer.join("token").unwrap();
    let scope = [ScopeToken::Profile].into_iter().collect::<Scope>();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("grant_type")
                .filter(|s| *s == "client_credentials")
                .is_none()
            {
                println!("Wrong or missing grant type");
                return false;
            }
            if query_pairs
                .get("scope")
                .filter(|s| *s == "profile")
                .is_none()
            {
                println!("Wrong or missing scope");
                return false;
            }
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
                scope: Some(scope.clone()),
            }),
        )
        .mount(&mock_server)
        .await;

    let response = access_token_with_client_credentials(
        &http_service,
        client_credentials,
        &token_endpoint,
        Some(scope),
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(response.access_token, ACCESS_TOKEN);
    assert_eq!(response.refresh_token, None);
    assert!(response.scope.unwrap().contains_token(&ScopeToken::Profile));
}
