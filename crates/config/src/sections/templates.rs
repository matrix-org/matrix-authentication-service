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

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ConfigurationSection;

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_path() -> Utf8PathBuf {
    "./templates/".into()
}

#[cfg(feature = "docker")]
fn default_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/templates/".into()
}

#[cfg(feature = "dist")]
fn default_path() -> Utf8PathBuf {
    "./share/templates/".into()
}

fn is_default_path(value: &Utf8PathBuf) -> bool {
    *value == default_path()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_assets_path() -> Utf8PathBuf {
    "./frontend/dist/manifest.json".into()
}

#[cfg(feature = "docker")]
fn default_assets_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/manifest.json".into()
}

#[cfg(feature = "dist")]
fn default_assets_path() -> Utf8PathBuf {
    "./share/manifest.json".into()
}

fn is_default_assets_path(value: &Utf8PathBuf) -> bool {
    *value == default_assets_path()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_translations_path() -> Utf8PathBuf {
    "./translations/".into()
}

#[cfg(feature = "docker")]
fn default_translations_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/translations/".into()
}

#[cfg(feature = "dist")]
fn default_translations_path() -> Utf8PathBuf {
    "./share/translations/".into()
}

fn is_default_translations_path(value: &Utf8PathBuf) -> bool {
    *value == default_translations_path()
}

/// Configuration related to templates
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TemplatesConfig {
    /// Path to the folder which holds the templates
    #[serde(default = "default_path", skip_serializing_if = "is_default_path")]
    #[schemars(with = "Option<String>")]
    pub path: Utf8PathBuf,

    /// Path to the assets manifest
    #[serde(
        default = "default_assets_path",
        skip_serializing_if = "is_default_assets_path"
    )]
    #[schemars(with = "Option<String>")]
    pub assets_manifest: Utf8PathBuf,

    /// Path to the translations
    #[serde(
        default = "default_translations_path",
        skip_serializing_if = "is_default_translations_path"
    )]
    #[schemars(with = "Option<String>")]
    pub translations_path: Utf8PathBuf,
}

impl Default for TemplatesConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
            assets_manifest: default_assets_path(),
            translations_path: default_translations_path(),
        }
    }
}

impl TemplatesConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        is_default_path(&self.path)
            && is_default_assets_path(&self.assets_manifest)
            && is_default_translations_path(&self.translations_path)
    }
}

impl ConfigurationSection for TemplatesConfig {
    const PATH: Option<&'static str> = Some("templates");
}
