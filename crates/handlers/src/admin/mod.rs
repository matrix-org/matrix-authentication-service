// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use aide::{
    axum::ApiRouter,
    openapi::{OAuth2Flow, OAuth2Flows, OpenApi, SecurityScheme, Server, ServerVariable},
};
use axum::{
    extract::{FromRef, FromRequestParts},
    Json, Router,
};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use indexmap::IndexMap;
use mas_http::CorsLayerExt;
use mas_matrix::BoxHomeserverConnection;
use mas_router::{OAuth2AuthorizationEndpoint, OAuth2TokenEndpoint, SimpleRoute};
use mas_storage::BoxRng;
use tower_http::cors::{Any, CorsLayer};

mod call_context;
mod model;
mod params;
mod response;
mod v1;

use self::call_context::CallContext;

pub fn router<S>() -> (OpenApi, Router<S>)
where
    S: Clone + Send + Sync + 'static,
    BoxHomeserverConnection: FromRef<S>,
    BoxRng: FromRequestParts<S>,
    CallContext: FromRequestParts<S>,
{
    let mut api = OpenApi::default();
    let router = ApiRouter::<S>::new()
        .nest("/api/admin/v1", self::v1::router())
        .finish_api_with(&mut api, |t| {
            t.title("Matrix Authentication Service admin API")
                .security_scheme(
                    "oauth2",
                    SecurityScheme::OAuth2 {
                        flows: OAuth2Flows {
                            client_credentials: Some(OAuth2Flow::ClientCredentials {
                                refresh_url: Some(OAuth2TokenEndpoint::PATH.to_owned()),
                                token_url: OAuth2TokenEndpoint::PATH.to_owned(),
                                scopes: IndexMap::from([(
                                    "urn:mas:admin".to_owned(),
                                    "Grant access to the admin API".to_owned(),
                                )]),
                            }),
                            authorization_code: Some(OAuth2Flow::AuthorizationCode {
                                authorization_url: OAuth2AuthorizationEndpoint::PATH.to_owned(),
                                refresh_url: Some(OAuth2TokenEndpoint::PATH.to_owned()),
                                token_url: OAuth2TokenEndpoint::PATH.to_owned(),
                                scopes: IndexMap::from([(
                                    "urn:mas:admin".to_owned(),
                                    "Grant access to the admin API".to_owned(),
                                )]),
                            }),
                            implicit: None,
                            password: None,
                        },
                        description: None,
                        extensions: IndexMap::default(),
                    },
                )
                .security_requirement_scopes("oauth2", ["urn:mas:admin"])
                .server(Server {
                    url: "{base}".to_owned(),
                    variables: IndexMap::from([(
                        "base".to_owned(),
                        ServerVariable {
                            default: "/".to_owned(),
                            ..ServerVariable::default()
                        },
                    )]),
                    ..Server::default()
                })
        });

    let router = router
        // Serve the OpenAPI spec as JSON
        .route(
            "/api/spec.json",
            axum::routing::get({
                let res = Json(api.clone());
                move || std::future::ready(res.clone())
            }),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_otel_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]),
        );

    (api, router)
}
