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

use figment::{
    error::Error as FigmentError,
    providers::{Env, Format, Yaml},
    Figment,
};
use serde::Deserialize;

mod csrf;
mod database;
mod http;
mod oauth2;
mod session;

pub use self::{
    csrf::Config as CsrfConfig,
    database::Config as DatabaseConfig,
    http::Config as HttpConfig,
    oauth2::{ClientConfig as OAuth2ClientConfig, Config as OAuth2Config},
    session::Config as SessionConfig,
};

#[derive(Debug, Deserialize)]
pub struct RootConfig {
    #[serde(default)]
    pub oauth2: OAuth2Config,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    pub csrf: CsrfConfig,

    pub session: SessionConfig,
}

impl RootConfig {
    pub fn load() -> Result<RootConfig, FigmentError> {
        Figment::new()
            .merge(Env::prefixed("MAS_").split("_"))
            .merge(Yaml::file("config.yaml"))
            .extract()
    }
}
