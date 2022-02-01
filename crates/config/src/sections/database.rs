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

use std::{num::NonZeroU32, path::PathBuf, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use sqlx::{
    postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    ConnectOptions,
};
use tracing::log::LevelFilter;

use super::ConfigurationSection;
use crate::schema;

fn default_connection_string() -> String {
    "postgresql://".to_string()
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

#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
enum ConnectConfig {
    Uri {
        /// Connection URI
        #[schemars(url, default = "default_connection_string")]
        uri: String,
    },
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
        socket: Option<PathBuf>,

        /// PostgreSQL user name to connect as
        #[serde(default)]
        username: Option<String>,

        /// Password to be used if the server demands password authentication
        #[serde(default)]
        password: Option<String>,

        /// The database name
        #[serde(default)]
        database: Option<String>,
        /* TODO
         * ssl_mode: PgSslMode,
         * ssl_root_cert: Option<CertificateInput>, */
    },
}

impl TryInto<PgConnectOptions> for &ConnectConfig {
    type Error = sqlx::Error;

    fn try_into(self) -> Result<PgConnectOptions, Self::Error> {
        match self {
            ConnectConfig::Uri { uri } => uri.parse(),
            ConnectConfig::Options {
                host,
                port,
                socket,
                username,
                password,
                database,
            } => {
                let mut opts =
                    PgConnectOptions::new().application_name("matrix-authentication-service");

                if let Some(host) = host {
                    opts = opts.host(host);
                }

                if let Some(port) = port {
                    opts = opts.port(*port);
                }

                if let Some(socket) = socket {
                    opts = opts.socket(socket);
                }

                if let Some(username) = username {
                    opts = opts.username(username);
                }

                if let Some(password) = password {
                    opts = opts.password(password);
                }

                if let Some(database) = database {
                    opts = opts.database(database);
                }

                Ok(opts)
            }
        }
    }
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
    options: ConnectConfig,

    /// Set the maximum number of connections the pool should maintain
    #[serde(default = "default_max_connections")]
    max_connections: NonZeroU32,

    /// Set the minimum number of connections the pool should maintain
    #[serde(default)]
    min_connections: u32,

    /// Set the amount of time to attempt connecting to the database
    #[schemars(with = "u64")]
    #[serde(default = "default_connect_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    connect_timeout: Duration,

    /// Set a maximum idle duration for individual connections
    #[schemars(with = "Option<u64>")]
    #[serde(default = "default_idle_timeout")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    idle_timeout: Option<Duration>,

    /// Set the maximum lifetime of individual connections
    #[schemars(with = "u64")]
    #[serde(default = "default_max_lifetime")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    max_lifetime: Option<Duration>,
}

impl DatabaseConfig {
    /// Connect to the database
    #[tracing::instrument(err, skip_all)]
    pub async fn connect(&self) -> anyhow::Result<PgPool> {
        let mut options: PgConnectOptions = (&self.options)
            .try_into()
            .context("invalid database config")?;

        options
            .log_statements(LevelFilter::Debug)
            .log_slow_statements(LevelFilter::Warn, Duration::from_millis(100));

        PgPoolOptions::new()
            .max_connections(self.max_connections.into())
            .min_connections(self.min_connections)
            .connect_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect_with(options)
            .await
            .context("could not connect to the database")
    }
}

#[async_trait]
impl ConfigurationSection<'_> for DatabaseConfig {
    fn path() -> &'static str {
        "database"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
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
