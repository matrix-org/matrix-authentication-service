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

mod http;
mod oauth2;

pub use self::http::Config as HttpConfig;
pub use self::oauth2::{ClientConfig as OAuth2ClientConfig, Config as OAuth2Config};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RootConfig {
    pub oauth2: OAuth2Config,
    pub http: HttpConfig,
}

impl RootConfig {
    pub fn load() -> Result<RootConfig, FigmentError> {
        Figment::new()
            .merge(Env::prefixed("MAS_").split("_"))
            .merge(Yaml::file("config.yaml"))
            .extract()
    }
}
