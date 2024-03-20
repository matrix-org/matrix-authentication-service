// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::borrow::Cow;

use anyhow::bail;
use async_trait::async_trait;
use camino::Utf8PathBuf;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

fn default_schemes() -> Vec<HashingScheme> {
    vec![HashingScheme {
        version: 1,
        algorithm: Algorithm::Argon2id,
        secret: None,
    }]
}

fn default_enabled() -> bool {
    true
}

/// User password hashing config
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PasswordsConfig {
    /// Whether password-based authentication is enabled
    #[serde(default = "default_enabled")]
    enabled: bool,

    #[serde(default = "default_schemes")]
    schemes: Vec<HashingScheme>,
}

impl Default for PasswordsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            schemes: default_schemes(),
        }
    }
}

#[async_trait]
impl ConfigurationSection for PasswordsConfig {
    const PATH: Option<&'static str> = Some("passwords");

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

impl PasswordsConfig {
    /// Whether password-based authentication is enabled
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Load the password hashing schemes defined by the config
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid, or if the secret file could
    /// not be read.
    pub async fn load(&self) -> Result<Vec<(u16, Algorithm, Option<Vec<u8>>)>, anyhow::Error> {
        let mut schemes: Vec<&HashingScheme> = self.schemes.iter().collect();
        schemes.sort_unstable_by_key(|a| a.version);
        schemes.dedup_by_key(|a| a.version);
        schemes.reverse();

        if schemes.len() != self.schemes.len() {
            // Some schemes had duplicated versions
            bail!("Multiple password schemes have the same versions");
        }

        if schemes.is_empty() {
            bail!("Requires at least one password scheme in the config");
        }

        let mut mapped_result = Vec::with_capacity(schemes.len());

        for scheme in schemes {
            let secret = if let Some(secret_or_file) = &scheme.secret {
                Some(secret_or_file.load().await?.into_owned())
            } else {
                None
            };

            mapped_result.push((scheme.version, scheme.algorithm, secret));
        }

        Ok(mapped_result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretOrFile {
    Secret(String),
    #[schemars(with = "String")]
    SecretFile(Utf8PathBuf),
}

impl SecretOrFile {
    async fn load(&self) -> Result<Cow<'_, [u8]>, std::io::Error> {
        match self {
            Self::Secret(secret) => Ok(Cow::Borrowed(secret.as_bytes())),
            Self::SecretFile(path) => {
                let secret = tokio::fs::read(path).await?;
                Ok(Cow::Owned(secret))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HashingScheme {
    version: u16,

    #[serde(flatten)]
    algorithm: Algorithm,

    #[serde(flatten)]
    secret: Option<SecretOrFile>,
}

fn default_bcrypt_cost() -> u32 {
    12
}

/// A hashing algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase", tag = "algorithm")]
pub enum Algorithm {
    /// bcrypt
    Bcrypt {
        /// Hashing cost
        #[serde(default = "default_bcrypt_cost")]
        cost: u32,
    },

    /// argon2id
    Argon2id,

    /// PBKDF2
    Pbkdf2,
}
