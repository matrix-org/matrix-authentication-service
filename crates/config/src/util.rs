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

use anyhow::Context;
use async_trait::async_trait;
use camino::Utf8Path;
use figment::{
    error::Error as FigmentError,
    providers::{Env, Format, Serialized, Yaml},
    Figment, Profile,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[async_trait]
/// Trait implemented by all configuration section to help loading specific part
/// of the config and generate the sample config.
pub trait ConfigurationSection<'a>: Sized + Deserialize<'a> + Serialize {
    /// Specify where this section should live relative to the root.
    fn path() -> &'static str;

    /// Generate a sample configuration for this section.
    async fn generate<R>(rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send;

    /// Generate a sample configuration and override it with environment
    /// variables.
    ///
    /// This is what backs the `config generate` subcommand, allowing to
    /// programatically generate a configuration file, e.g.
    ///
    /// ```sh
    /// export MAS_OAUTH2_ISSUER=https://example.com/
    /// export MAS_HTTP_ADDRESS=127.0.0.1:1234
    /// matrix-authentication-service config generate
    /// ```
    async fn load_and_generate<R>(rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        let base = Self::generate(rng)
            .await
            .context("could not generate configuration")?;

        Figment::new()
            .merge(Serialized::from(&base, Profile::Default))
            .merge(Env::prefixed("MAS_").split("_"))
            .extract_inner(Self::path())
            .context("could not load configuration")
    }

    /// Load configuration from a list of files and environment variables.
    fn load_from_files<P>(paths: &[P]) -> Result<Self, FigmentError>
    where
        P: AsRef<Utf8Path>,
    {
        let base = Figment::new().merge(Env::prefixed("MAS_").split("_"));

        paths
            .iter()
            .fold(base, |f, path| f.merge(Yaml::file(path.as_ref())))
            .extract_inner(Self::path())
    }

    /// Load configuration from a file and environment variables.
    fn load_from_file<P>(path: P) -> Result<Self, FigmentError>
    where
        P: AsRef<Utf8Path>,
    {
        Self::load_from_files(&[path])
    }

    /// Generate config used in unit tests
    fn test() -> Self;
}
