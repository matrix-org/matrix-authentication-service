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

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;
use crate::schema;

#[allow(clippy::unnecessary_wraps)]
fn default_connection_string() -> Option<String> {
    Some("postgresql://".to_owned())
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
            uri: default_connection_string(),
            host: None,
            port: None,
            socket: None,
            username: None,
            password: None,
            database: None,
            max_connections: default_max_connections(),
            min_connections: Default::default(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            max_lifetime: default_max_lifetime(),
        }
    }
}

/// Database connection configuration
#[serde_as]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    /// Connection URI
    ///
    /// This must not be specified if `host`, `port`, `socket`, `username`,
    /// `password`, or `database` are specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "default_connection_string")]
    pub uri: Option<String>,

    /// Name of host to connect to
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option::<schema::Hostname>")]
    pub host: Option<String>,

    /// Port number to connect at the server host
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: Option<u16>,

    /// Directory containing the UNIX socket to connect to
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub socket: Option<Utf8PathBuf>,

    /// PostgreSQL user name to connect as
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password to be used if the server demands password authentication
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// The database name
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,

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
    #[serde(
        default = "default_idle_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub idle_timeout: Option<Duration>,

    /// Set the maximum lifetime of individual connections
    #[schemars(with = "u64")]
    #[serde(
        default = "default_max_lifetime",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub max_lifetime: Option<Duration>,
}

impl ConfigurationSection for DatabaseConfig {
    const PATH: Option<&'static str> = Some("database");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::error::Error> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        // Check that the user did not specify both `uri` and the split options at the
        // same time
        let has_split_options = self.host.is_some()
            || self.port.is_some()
            || self.socket.is_some()
            || self.username.is_some()
            || self.password.is_some()
            || self.database.is_some();

        if self.uri.is_some() && has_split_options {
            let mut error = figment::error::Error::from(
                "uri must not be specified if host, port, socket, username, password, or database are specified".to_owned(),
            );
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), "uri".to_owned()];
            return Err(error);
        }

        Ok(())
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
                config.uri.as_deref(),
                Some("postgresql://user:password@host/database")
            );

            Ok(())
        });
    }
}
