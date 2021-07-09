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

use std::time::Duration;

use csrf::{AesGcmCsrfProtection, CsrfProtection};
use serde::Deserialize;
use serde_with::serde_as;
use tide::Middleware;

use crate::middlewares::CsrfMiddleware;

fn default_ttl() -> Duration {
    Duration::from_secs(3600)
}

fn default_cookie_name() -> String {
    "csrf".to_string()
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde_as(as = "serde_with::hex::Hex")]
    key: [u8; 32],

    #[serde(default = "default_cookie_name")]
    cookie_name: String,

    #[serde(default = "default_ttl")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    ttl: Duration,
}

impl Config {
    pub fn into_protection(self) -> impl CsrfProtection {
        AesGcmCsrfProtection::from_key(self.key)
    }

    pub fn into_middleware<State: Clone + Send + Sync + 'static>(self) -> impl Middleware<State> {
        let ttl = self.ttl;
        let cookie_name = self.cookie_name.clone();
        let protection = self.into_protection();
        CsrfMiddleware::new(protection, cookie_name, ttl)
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }
}
