// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::path::PathBuf;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

fn default_http_address() -> String {
    "[::]:8080".into()
}

fn default_public_base() -> Url {
    "http://[::]:8080".parse().unwrap()
}

fn http_address_example_1() -> &'static str {
    "[::1]:8080"
}
fn http_address_example_2() -> &'static str {
    "[::]:8080"
}
fn http_address_example_3() -> &'static str {
    "127.0.0.1:8080"
}
fn http_address_example_4() -> &'static str {
    "0.0.0.0:8080"
}

/// Configuration related to the web server
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// IP and port the server should listen to
    #[schemars(
        example = "http_address_example_1",
        example = "http_address_example_2",
        example = "http_address_example_3",
        example = "http_address_example_4"
    )]
    #[serde(default = "default_http_address")]
    pub address: String,

    /// Path from which to serve static files. If not specified, it will serve
    /// the static files embedded in the server binary
    #[serde(default)]
    pub web_root: Option<PathBuf>,

    /// Public URL base from where the authentication service is reachable
    pub public_base: Url,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            address: default_http_address(),
            web_root: None,
            public_base: default_public_base(),
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for HttpConfig {
    fn path() -> &'static str {
        "http"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
