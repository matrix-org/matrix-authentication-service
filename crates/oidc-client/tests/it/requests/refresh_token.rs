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
use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_oidc_client::requests::refresh_token::refresh_access_token;
use oauth2_types::requests::AccessTokenResponse;
use rand::SeedableRng;
use wiremock::{
    matchers::{method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{client_credentials, init_test, now, ACCESS_TOKEN, CLIENT_ID, REFRESH_TOKEN};

#[tokio::test]
async fn pass_refresh_access_token() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(OAuthClientAuthenticationMethod::None, &issuer, None);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("grant_type")
                .filter(|s| *s == "refresh_token")
                .is_none()
            {
                println!("Wrong or missing grant type");
                return false;
            }
            if query_pairs
                .get("refresh_token")
                .filter(|s| *s == REFRESH_TOKEN)
                .is_none()
            {
                println!("Wrong or missing refresh token");
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

    let (response, response_id_token) = refresh_access_token(
        &http_service,
        client_credentials,
        &token_endpoint,
        REFRESH_TOKEN.to_owned(),
        None,
        None,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(response.access_token, ACCESS_TOKEN);
    assert_eq!(response.refresh_token, None);
    assert_matches!(response_id_token, None);
}
