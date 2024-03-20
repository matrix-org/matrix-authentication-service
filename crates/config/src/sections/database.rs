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

use std::{num::NonZeroU32, time::Duration};

use async_trait::async_trait;
use camino::Utf8PathBuf;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use super::ConfigurationSection;
use crate::schema;

fn default_connection_string() -> String {
    "postgresql://".to_owned()
}

fn default_max_connections() -> NonZeroU32 {
    NonZeroU32::new(10).unwrap()
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
            options: ConnectConfig::default(),
            max_connections: default_max_connections(),
            min_connections: Default::default(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            max_lifetime: default_max_lifetime(),
        }
    }
}

/// Database connection configuration
#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum ConnectConfig {
    /// Connect via a full URI
    Uri {
        /// Connection URI
        #[schemars(url, default = "default_connection_string")]
        uri: String,
    },
    /// Connect via a map of options
    Options {
        /// Name of host to connect to
        #[schemars(schema_with = "schema::hostname")]
        #[serde(default)]
        host: Option<String>,

        /// Port number to connect at the server host
        #[schemars(schema_with = "schema::port")]
        #[serde(default)]
        port: Option<u16>,

        /// Directory containing the UNIX socket to connect to
        #[serde(default)]
        #[schemars(with = "Option<String>")]
        socket: Option<Utf8PathBuf>,

        /// PostgreSQL user name to connect as
        #[serde(default)]
        username: Option<String>,

        /// Password to be used if the server demands password authentication
        #[serde(default)]
        password: Option<String>,

        /// The database name
        #[serde(default)]
        database: Option<String>,
    },
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self::Uri {
            uri: default_connection_string(),
        }
    }
}

/// Database connection configuration
#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    /// Options related to how to connect to the database
    #[serde(default, flatten)]
    pub options: ConnectConfig,

    /// Set the maximum number of connections the pool should maintain
    #[serde(default = "default_max_connections")]
    pub max_connections: NonZeroU32,

    /// Set the minimum number of connections the pool should maintain
    #[serde(default)]
    pub min_connections: u32,

    /// Set the amount of time to attempt connecting to the database
    #[schemars(with = "u64")]
    #[serde(default = "default_connect_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub connect_timeout: Duration,

    /// Set a maximum idle duration for individual connections
    #[schemars(with = "Option<u64>")]
    #[serde(default = "default_idle_timeout")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub idle_timeout: Option<Duration>,

    /// Set the maximum lifetime of individual connections
    #[schemars(with = "u64")]
    #[serde(default = "default_max_lifetime")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub max_lifetime: Option<Duration>,
}

#[async_trait]
impl ConfigurationSection for DatabaseConfig {
    fn path() -> &'static str {
        "database"
    }

    async fn generate<R>(_rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Yaml},
        Figment, Jail,
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    database:
                      uri: postgresql://user:password@host/database
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<DatabaseConfig>("database")?;

            assert_eq!(
                config.options,
                ConnectConfig::Uri {
                    uri: "postgresql://user:password@host/database".to_string()
                }
            );

            Ok(())
        });
    }
}
