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
use chrono::Duration;
use hyper::StatusCode;
use mas_data_model::{AccessToken, Client, TokenType, User};
use mas_storage::{oauth2::OAuth2ClientRepository, RepositoryAccess};
use oauth2_types::scope::{Scope, ScopeToken, OPENID};
use sqlx::PgPool;

use crate::test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState};

async fn create_test_client(state: &TestState) -> Client {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let client = repo
        .oauth2_client()
        .add(
            &mut rng,
            &state.clock,
            vec![],
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    client
}

async fn create_test_user<U: Into<String> + Send>(state: &TestState, username: U) -> User {
    let username = username.into();
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let user = repo
        .user()
        .add(&mut rng, &state.clock, username)
        .await
        .unwrap();

    repo.save().await.unwrap();

    user
}

async fn start_oauth_session(
    state: &TestState,
    client: &Client,
    user: &User,
    scope: Scope,
) -> AccessToken {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let browser_session = repo
        .browser_session()
        .add(&mut rng, &state.clock, user, None)
        .await
        .unwrap();

    let session = repo
        .oauth2_session()
        .add_from_browser_session(&mut rng, &state.clock, client, &browser_session, scope)
        .await
        .unwrap();

    let access_token_str = TokenType::AccessToken.generate(&mut rng);

    let access_token = repo
        .oauth2_access_token()
        .add(
            &mut rng,
            &state.clock,
            &session,
            access_token_str,
            Duration::minutes(5),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    access_token
}

const GRAPHQL: ScopeToken = ScopeToken::from_static("urn:mas:graphql:*");
const ADMIN: ScopeToken = ScopeToken::from_static("urn:mas:admin");

#[derive(serde::Deserialize)]
struct GraphQLResponse {
    #[serde(default)]
    data: serde_json::Value,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

/// Test that the GraphQL endpoint can be queried with a GET request.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_get(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    let request = Request::get("/graphql?query={viewer{__typename}}").empty();

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "Anonymous",
            },
        })
    );
}

/// Test that the GraphQL endpoint can be queried with a POST request
/// anonymously.
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

    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "Anonymous",
            },
        })
    );
}

/// Test that the GraphQL endpoint can be authenticated with a bearer token.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_viewer(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and a token
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL])).await;
    let access_token = access_token.access_token;

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

    assert!(response.errors.is_empty());
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

/// Test that the GraphQL endpoint requires the GraphQL scope.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_no_scope(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and a token
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([OPENID])).await;
    let access_token = access_token.access_token;

    let req = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                query {
                    viewer {
                        __typename
                    }
                }
            "#,
        }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let response: GraphQLResponse = response.json();

    assert_eq!(
        response.errors,
        vec![serde_json::json!({
            "message": "Missing urn:mas:graphql:* scope",
        })]
    );
    assert_eq!(response.data, serde_json::json!(null));
}

/// Test the admin scope on the GraphQL endpoint.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_admin(pool: PgPool) {
    init_tracing();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and two tokens
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;

    // Regular access token
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL])).await;
    let access_token = access_token.access_token;

    // Admin access token
    let access_token_admin =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL, ADMIN])).await;
    let access_token_admin = access_token_admin.access_token;

    // Create a second user and try to query stuff about it
    let user2 = create_test_user(&state, "bob").await;

    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                query UserQuery($id: ID) {
                    user(id: $id) {
                        id
                        username
                    }
                }
            "#, 
            "variables": {
                "id": format!("user:{id}", id = user2.id),
            },
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    // It should not find the user, because it's not the owner and not an admin
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "user": null,
        })
    );

    // Do the same request with the admin token
    let request = Request::post("/graphql")
        .bearer(&access_token_admin)
        .json(serde_json::json!({
            "query": r#"
                query UserQuery($id: ID) {
                    user(id: $id) {
                        id
                        username
                    }
                }
            "#, 
            "variables": {
                "id": format!("user:{id}", id = user2.id),
            },
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    // It should find the user, because the token has the admin scope
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "user": {
                "id": format!("user:{id}", id = user2.id),
                "username": "bob",
            },
        })
    );
}
