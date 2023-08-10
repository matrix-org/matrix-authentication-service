// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use axum::http::Request;
use hyper::StatusCode;
use mas_data_model::AuthorizationCode;
use mas_router::SimpleRoute;
use oauth2_types::{
    registration::ClientRegistrationResponse,
    requests::{AccessTokenResponse, ResponseMode},
    scope::{Scope, ScopeToken, OPENID},
};
use sqlx::PgPool;

use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

const GRAPHQL_SCOPE: ScopeToken = ScopeToken::from_static("urn:mas:graphql:*");

#[derive(serde::Deserialize)]
struct GraphQLResponse {
    data: serde_json::Value,
    errors: Option<Vec<serde_json::Value>>,
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_anonymous_viewer(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    let req = Request::post("/graphql").json(serde_json::json!({
        "query": r#"
            query {
                viewer {
                    __typename
                }
            }
        "#,
    }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert_eq!(response.errors, None);
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "Anonymous",
            },
        })
    );
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_viewer(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and a token
    // XXX: this is a lot of boilerplate just to get an access token!

    // Provision a client
    let request =
        Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
            "client_uri": "https://example.com/",
            "redirect_uris": ["https://example.com/callback"],
            "contacts": ["contact@example.com"],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);

    let ClientRegistrationResponse { client_id, .. } = response.json();

    // Let's provision a user and create a session for them.
    let mut repo = state.repository().await.unwrap();

    let user = repo
        .user()
        .add(&mut state.rng(), &state.clock, "alice".to_owned())
        .await
        .unwrap();

    let browser_session = repo
        .browser_session()
        .add(&mut state.rng(), &state.clock, &user)
        .await
        .unwrap();

    // Lookup the client in the database.
    let client = repo
        .oauth2_client()
        .find_by_client_id(&client_id)
        .await
        .unwrap()
        .unwrap();

    // Start a grant
    let code = "thisisaverysecurecode";
    let grant = repo
        .oauth2_authorization_grant()
        .add(
            &mut state.rng(),
            &state.clock,
            &client,
            "https://example.com/redirect".parse().unwrap(),
            Scope::from_iter([OPENID, GRAPHQL_SCOPE]),
            Some(AuthorizationCode {
                code: code.to_owned(),
                pkce: None,
            }),
            Some("state".to_owned()),
            Some("nonce".to_owned()),
            None,
            ResponseMode::Query,
            false,
            false,
        )
        .await
        .unwrap();

    let session = repo
        .oauth2_session()
        .add(
            &mut state.rng(),
            &state.clock,
            &client,
            &browser_session,
            grant.scope.clone(),
        )
        .await
        .unwrap();

    // And fulfill it
    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&state.clock, &session, grant)
        .await
        .unwrap();

    repo.save().await.unwrap();

    // Now call the token endpoint to get an access token.
    let request = Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": grant.redirect_uri,
        "client_id": client.client_id,
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let AccessTokenResponse { access_token, .. } = response.json();

    let req = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                query {
                    viewer {
                        __typename
                        
                        ... on User {
                            id
                            username
                        }
                    }
                }
            "#,
        }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert_eq!(response.errors, None);
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "User",
                "id": format!("user:{id}", id = user.id),
                "username": "alice",
            },
        })
    );
}
