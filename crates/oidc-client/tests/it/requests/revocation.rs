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

use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_oidc_client::requests::revocation::revoke_token;
use rand::SeedableRng;
use wiremock::{
    matchers::{method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{client_credentials, init_test, ACCESS_TOKEN, CLIENT_ID};

#[tokio::test]
async fn pass_revoke_token() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(OAuthClientAuthenticationMethod::None, &issuer, None);
    let revocation_endpoint = issuer.join("revoke").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("token")
                .filter(|s| *s == ACCESS_TOKEN)
                .is_none()
            {
                println!("Wrong or missing refresh token");
                return false;
            }
            if query_pairs
                .get("token_type_hint")
                .filter(|s| *s == "access_token")
                .is_none()
            {
                println!("Wrong or missing token type hint");
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
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    revoke_token(
        &http_service,
        client_credentials,
        &revocation_endpoint,
        ACCESS_TOKEN.to_owned(),
        Some(OAuthTokenTypeHint::AccessToken),
        crate::now(),
        &mut rng,
    )
    .await
    .unwrap();
}
