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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use sqlx::postgres::{PgPool, PgPoolOptions};

fn default_uri() -> String {
    "postgresql://".to_string()
}

fn default_max_connections() -> u32 {
    10
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(30)
}

#[allow(clippy::unnecessary_wraps)]
fn default_idle_timeout() -> Option<Duration> {
    Some(Duration::from_secs(10 * 60))
}

#[allow(clippy::unnecessary_wraps)]
fn default_max_lifetime() -> Option<Duration> {
    Some(Duration::from_secs(30 * 60))
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            uri: default_uri(),
            max_connections: default_max_connections(),
            min_connections: Default::default(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            max_lifetime: default_max_lifetime(),
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    #[serde(default = "default_uri")]
    uri: String,

    #[serde(default = "default_max_connections")]
    max_connections: u32,

    #[serde(default)]
    min_connections: u32,

    #[serde(default = "default_connect_timeout")]
    connect_timeout: Duration,

    #[serde(default = "default_idle_timeout")]
    idle_timeout: Option<Duration>,

    #[serde(default = "default_max_lifetime")]
    max_lifetime: Option<Duration>,
}

impl DatabaseConfig {
    #[tracing::instrument(err)]
    pub async fn connect(&self) -> Result<PgPool, sqlx::Error> {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .connect_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect(&self.uri)
            .await
    }
}
