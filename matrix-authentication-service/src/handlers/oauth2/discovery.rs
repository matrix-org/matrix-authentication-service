// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use async_trait::async_trait;
use oauth2_types::oidc::Metadata;
use tide::{Body, Endpoint, Request, Response};

use crate::config::OAuth2Config;

pub struct MetadataEndpoint(Metadata);

impl MetadataEndpoint {
    pub fn from_config(config: &OAuth2Config) -> Self {
        let base = config.issuer.clone();
        MetadataEndpoint(Metadata {
            authorization_endpoint: base.join("oauth2/authorize").ok(),
            token_endpoint: base.join("oauth2/token").ok(),
            jwks_uri: base.join(".well-known/jwks.json").ok(),
            issuer: base,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: None,
            response_modes_supported: None,
            grant_types_supported: None,
            code_challenge_methods_supported: None,
        })
    }
}

#[async_trait]
impl<State> Endpoint<State> for MetadataEndpoint
where
    State: Clone + Sync + Send + 'static,
{
    async fn call(&self, _req: Request<State>) -> tide::Result {
        let body = Body::from_json(&self.0)?;
        Ok(Response::builder(200)
            .body(body)
            .content_type(tide::http::mime::JSON)
            .build())
    }
}
