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

use figment::{error::Error as FigmentError, Figment};
use serde::de::DeserializeOwned;

/// Trait implemented by all configuration section to help loading specific part
/// of the config and generate the sample config.
pub trait ConfigurationSection: Sized + DeserializeOwned {
    /// Specify where this section should live relative to the root.
    const PATH: Option<&'static str> = None;

    /// Validate the configuration section
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    fn validate(&self, _figment: &Figment) -> Result<(), FigmentError> {
        Ok(())
    }

    /// Extract configuration from a Figment instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration could not be loaded
    fn extract(figment: &Figment) -> Result<Self, FigmentError> {
        let this: Self = if let Some(path) = Self::PATH {
            figment.extract_inner(path)?
        } else {
            figment.extract()?
        };

        this.validate(figment)?;
        Ok(this)
    }
}

/// Extension trait for [`ConfigurationSection`] to allow extracting the
/// configuration section from a [`Figment`] or return the default value if the
/// section is not present.
pub trait ConfigurationSectionExt: ConfigurationSection + Default {
    /// Extract the configuration section from the given [`Figment`], or return
    /// the default value if the section is not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration section is invalid.
    fn extract_or_default(figment: &Figment) -> Result<Self, figment::Error> {
        let this: Self = if let Some(path) = Self::PATH {
            // If the configuration section is not present, we return the default value
            if !figment.contains(path) {
                return Ok(Self::default());
            }

            figment.extract_inner(path)?
        } else {
            figment.extract()?
        };

        this.validate(figment)?;
        Ok(this)
    }
}

impl<T: ConfigurationSection + Default> ConfigurationSectionExt for T {}
