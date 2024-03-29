// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::collections::{BTreeSet, HashMap};

use camino::{Utf8Path, Utf8PathBuf};
use thiserror::Error;

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEntry {
    #[allow(dead_code)]
    name: Option<String>,

    #[allow(dead_code)]
    src: Option<Utf8PathBuf>,

    file: Utf8PathBuf,

    css: Option<Vec<Utf8PathBuf>>,

    assets: Option<Vec<Utf8PathBuf>>,

    #[allow(dead_code)]
    is_entry: Option<bool>,

    #[allow(dead_code)]
    is_dynamic_entry: Option<bool>,

    imports: Option<Vec<Utf8PathBuf>>,

    dynamic_imports: Option<Vec<Utf8PathBuf>>,

    integrity: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Manifest {
    #[serde(flatten)]
    inner: HashMap<Utf8PathBuf, ManifestEntry>,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum FileType {
    Script,
    Stylesheet,
    Woff,
    Woff2,
    Json,
    Png,
}

impl FileType {
    fn from_name(name: &Utf8Path) -> Option<Self> {
        match name.extension() {
            Some("css") => Some(Self::Stylesheet),
            Some("js") => Some(Self::Script),
            Some("woff") => Some(Self::Woff),
            Some("woff2") => Some(Self::Woff2),
            Some("json") => Some(Self::Json),
            Some("png") => Some(Self::Png),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid Vite manifest")]
pub enum InvalidManifest<'a> {
    #[error("Can't find asset for name {name:?}")]
    CantFindAssetByName { name: &'a Utf8Path },

    #[error("Can't find asset for file {file:?}")]
    CantFindAssetByFile { file: &'a Utf8Path },

    #[error("Invalid file type")]
    InvalidFileType,
}

/// Represents an entry which should be preloaded and included
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Asset<'a> {
    file_type: FileType,
    name: &'a Utf8Path,
    integrity: Option<&'a str>,
}

impl<'a> Asset<'a> {
    fn new(entry: &'a ManifestEntry) -> Result<Self, InvalidManifest<'a>> {
        let name = &entry.file;
        let integrity = entry.integrity.as_deref();
        let file_type = FileType::from_name(name).ok_or(InvalidManifest::InvalidFileType)?;
        Ok(Self {
            file_type,
            name,
            integrity,
        })
    }

    fn src(&self, assets_base: &Utf8Path) -> Utf8PathBuf {
        assets_base.join(self.name)
    }

    /// Generate a `<link rel="preload">` tag to preload this entry
    pub fn preload_tag(&self, assets_base: &Utf8Path) -> String {
        let href = self.src(assets_base);
        let integrity = self
            .integrity
            .map(|i| format!(r#"integrity="{i}" "#))
            .unwrap_or_default();
        match self.file_type {
            FileType::Stylesheet => {
                format!(r#"<link rel="preload" href="{href}" as="style" crossorigin {integrity}/>"#)
            }
            FileType::Script => {
                format!(r#"<link rel="modulepreload" href="{href}" crossorigin {integrity}/>"#)
            }
            FileType::Woff | FileType::Woff2 => {
                format!(r#"<link rel="preload" href="{href}" as="font" crossorigin {integrity}/>"#,)
            }
            FileType::Json => {
                format!(r#"<link rel="preload" href="{href}" as="fetch" crossorigin {integrity}/>"#,)
            }
            FileType::Png => {
                format!(r#"<link rel="preload" href="{href}" as="image" crossorigin {integrity}/>"#,)
            }
        }
    }

    /// Generate a `<link>` or `<script>` tag to include this entry
    pub fn include_tag(&self, assets_base: &Utf8Path) -> Option<String> {
        let src = self.src(assets_base);
        let integrity = self
            .integrity
            .map(|i| format!(r#"integrity="{i}" "#))
            .unwrap_or_default();

        match self.file_type {
            FileType::Stylesheet => Some(format!(
                r#"<link rel="stylesheet" href="{src}" crossorigin {integrity}/>"#
            )),
            FileType::Script => Some(format!(
                r#"<script type="module" src="{src}" crossorigin {integrity}></script>"#
            )),
            FileType::Woff | FileType::Woff2 | FileType::Json | FileType::Png => None,
        }
    }

    /// Returns `true` if the asset type is a script
    #[must_use]
    pub fn is_script(&self) -> bool {
        self.file_type == FileType::Script
    }

    /// Returns `true` if the asset type is a stylesheet
    #[must_use]
    pub fn is_stylesheet(&self) -> bool {
        self.file_type == FileType::Stylesheet
    }

    /// Returns `true` if the asset type is JSON
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.file_type == FileType::Json
    }

    /// Returns `true` if the asset type is a font
    #[must_use]
    pub fn is_font(&self) -> bool {
        self.file_type == FileType::Woff || self.file_type == FileType::Woff2
    }

    /// Returns `true` if the asset type is image
    #[must_use]
    pub fn is_image(&self) -> bool {
        self.file_type == FileType::Png
    }
}

impl Manifest {
    /// Find all assets which should be loaded for a given entrypoint
    ///
    /// # Errors
    ///
    /// Returns an error if the entrypoint is invalid for this manifest
    pub fn assets_for<'a>(
        &'a self,
        entrypoint: &'a Utf8Path,
    ) -> Result<BTreeSet<Asset<'a>>, InvalidManifest<'a>> {
        let entry = self.lookup_by_name(entrypoint)?;
        let main_asset = Asset::new(entry)?;
        entry
            .css
            .iter()
            .flatten()
            .map(|name| self.lookup_by_file(name).and_then(Asset::new))
            .chain(std::iter::once(Ok(main_asset)))
            .collect()
    }

    /// Find all assets which should be preloaded for a given entrypoint
    ///
    /// # Errors
    ///
    /// Returns an error if the entrypoint is invalid for this manifest
    pub fn preload_for<'a>(
        &'a self,
        entrypoint: &'a Utf8Path,
    ) -> Result<BTreeSet<Asset<'a>>, InvalidManifest<'a>> {
        let entry = self.lookup_by_name(entrypoint)?;
        self.find_preload(entry)
    }

    /// Lookup an entry in the manifest by its original name
    fn lookup_by_name<'a>(
        &self,
        name: &'a Utf8Path,
    ) -> Result<&ManifestEntry, InvalidManifest<'a>> {
        self.inner
            .get(name)
            .ok_or(InvalidManifest::CantFindAssetByName { name })
    }

    /// Lookup an entry in the manifest by its output name
    fn lookup_by_file<'a>(
        &self,
        file: &'a Utf8Path,
    ) -> Result<&ManifestEntry, InvalidManifest<'a>> {
        self.inner
            .values()
            .find(|e| e.file == file)
            .ok_or(InvalidManifest::CantFindAssetByFile { file })
    }

    /// Recursively find all the assets that should be preloaded
    fn find_preload<'a>(
        &'a self,
        entry: &'a ManifestEntry,
    ) -> Result<BTreeSet<Asset<'a>>, InvalidManifest<'a>> {
        let mut entries = BTreeSet::new();
        self.find_preload_rec(entry, &mut entries)?;
        Ok(entries)
    }

    fn find_preload_rec<'a>(
        &'a self,
        current_entry: &'a ManifestEntry,
        entries: &mut BTreeSet<Asset<'a>>,
    ) -> Result<(), InvalidManifest<'a>> {
        let asset = Asset::new(current_entry)?;
        let inserted = entries.insert(asset);

        // If we inserted the entry, we need to find its dependencies
        if inserted {
            let css = current_entry.css.iter().flatten();
            let assets = current_entry.assets.iter().flatten();
            for name in css.chain(assets) {
                let entry = self.lookup_by_file(name)?;
                self.find_preload_rec(entry, entries)?;
            }

            let dynamic_imports = current_entry.dynamic_imports.iter().flatten();
            let imports = current_entry.imports.iter().flatten();
            for import in dynamic_imports.chain(imports) {
                let entry = self.lookup_by_name(import)?;
                self.find_preload_rec(entry, entries)?;
            }
        }

        Ok(())
    }
}
