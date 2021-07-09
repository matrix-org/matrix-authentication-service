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

use std::collections::HashSet;

use oauth2_types::oidc::Metadata;
use tide::{Body, Request, Response};

use crate::state::State;

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let m = Metadata {
        issuer: state.issuer(),
        authorization_endpoint: state.authorization_endpoint(),
        token_endpoint: state.token_endpoint(),
        jwks_uri: state.jwks_uri(),
        registration_endpoint: None,
        scopes_supported: HashSet::default(),
        response_types_supported: HashSet::default(),
        response_modes_supported: HashSet::default(),
        grant_types_supported: HashSet::default(),
    };

    let body = Body::from_json(&m)?;

    Ok(Response::builder(200).body(body).build())
}
