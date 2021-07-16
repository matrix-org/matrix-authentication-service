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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2ClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub redirect_uris: Option<Vec<Url>>,
}

fn default_oauth2_issuer() -> Url {
    "http://[::]:8080".parse().unwrap()
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2Config {
    #[serde(default = "default_oauth2_issuer")]
    pub issuer: Url,

    #[serde(default)]
    pub clients: Vec<OAuth2ClientConfig>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
        }
    }
}
