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

mod cookies;
mod csrf;
mod database;
mod http;
mod oauth2;
mod util;

pub use self::{
    cookies::CookiesConfig,
    csrf::CsrfConfig,
    database::DatabaseConfig,
    http::HttpConfig,
    oauth2::{Algorithm, KeySet, OAuth2ClientConfig, OAuth2Config},
    util::ConfigurationSection,
};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RootConfig {
    pub oauth2: OAuth2Config,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    pub cookies: CookiesConfig,

    #[serde(default)]
    pub csrf: CsrfConfig,
}

impl ConfigurationSection<'_> for RootConfig {
    fn path() -> &'static str {
        ""
    }

    fn generate() -> Self {
        Self {
            oauth2: OAuth2Config::generate(),
            http: HttpConfig::generate(),
            database: DatabaseConfig::generate(),
            cookies: CookiesConfig::generate(),
            csrf: CsrfConfig::generate(),
        }
    }
}
