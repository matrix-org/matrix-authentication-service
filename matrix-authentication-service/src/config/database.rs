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

use anyhow::Context;
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use sqlx::postgres::{PgPool, PgPoolOptions};

use super::ConfigurationSection;

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

fn duration_schema(gen: &mut SchemaGenerator) -> Schema {
    Option::<u64>::json_schema(gen)
}

fn optional_duration_schema(gen: &mut SchemaGenerator) -> Schema {
    u64::json_schema(gen)
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    #[serde(default = "default_uri")]
    uri: String,

    #[serde(default = "default_max_connections")]
    max_connections: u32,

    #[serde(default)]
    min_connections: u32,

    #[schemars(schema_with = "duration_schema")]
    #[serde(default = "default_connect_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    connect_timeout: Duration,

    #[schemars(schema_with = "optional_duration_schema")]
    #[serde(default = "default_idle_timeout")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    idle_timeout: Option<Duration>,

    #[schemars(schema_with = "optional_duration_schema")]
    #[serde(default = "default_max_lifetime")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    max_lifetime: Option<Duration>,
}

impl DatabaseConfig {
    #[tracing::instrument(err)]
    pub async fn connect(&self) -> anyhow::Result<PgPool> {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .connect_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect(&self.uri)
            .await
            .context("could not connect to the database")
    }
}

impl ConfigurationSection<'_> for DatabaseConfig {
    fn path() -> &'static str {
        "database"
    }

    fn generate() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use figment::Jail;

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    database:
                      uri: postgresql://user:password@host/database
                "#,
            )?;

            let config = DatabaseConfig::load_from_file("config.yaml")?;

            assert_eq!(config.uri, "postgresql://user:password@host/database");

            Ok(())
        })
    }
}
