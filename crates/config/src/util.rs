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

use async_trait::async_trait;
use figment::{error::Error as FigmentError, Figment};
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
/// Trait implemented by all configuration section to help loading specific part
/// of the config and generate the sample config.
pub trait ConfigurationSection: Sized + DeserializeOwned + Serialize {
    /// Specify where this section should live relative to the root.
    fn path() -> &'static str;

    /// Generate a sample configuration for this section.
    async fn generate<R>(rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send;

    /// Extract configuration from a Figment instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration could not be loaded
    fn extract(figment: &Figment) -> Result<Self, FigmentError> {
        figment.extract_inner(Self::path())
    }

    /// Generate config used in unit tests
    fn test() -> Self;
}
