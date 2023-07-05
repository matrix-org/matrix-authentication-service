use std::collections::{BTreeSet, HashMap};

use camino::{Utf8Path, Utf8PathBuf};
use thiserror::Error;

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEntry {
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

/// Render the HTML template
fn template(head: impl Iterator<Item = String>, config: &impl serde::Serialize) -> String {
    // This should be kept in sync with `../../../frontend/index.html`

    // Render the items to insert in the <head>
    let head: String = head.map(|f| format!("  {f}\n")).collect();
    // Serialize the config
    let config = serde_json::to_string(config).expect("failed to serialize config");

    // Script in the <head> which manages the dark mode class on the <html> element
    let dark_mode_script = r#"
    (function () {
      const query = window.matchMedia("(prefers-color-scheme: dark)");
      function handleChange(e) {
        if (e.matches) {
          document.documentElement.classList.add("dark")
        } else {
          document.documentElement.classList.remove("dark")
        }
      }
  
      query.addListener(handleChange);
      handleChange(query);
    })();
  "#;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>matrix-authentication-service</title>
  <script>window.APP_CONFIG = JSON.parse({config:?});</script>
  <script>{dark_mode_script}</script>
{head}</head>
<body>
  <div id="root"></div>
</body>
</html>"#
    )
}

#[derive(serde::Deserialize, Debug)]
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
}

impl FileType {
    fn from_name(name: &Utf8Path) -> Option<Self> {
        match name.extension() {
            Some("css") => Some(Self::Stylesheet),
            Some("js") => Some(Self::Script),
            Some("woff") => Some(Self::Woff),
            Some("woff2") => Some(Self::Woff2),
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
struct Asset<'a> {
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
    fn preload_tag(&self, assets_base: &Utf8Path) -> String {
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
        }
    }

    /// Generate a `<link>` or `<script>` tag to include this entry
    fn include_tag(&self, assets_base: &Utf8Path) -> Option<String> {
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
                r#"<script type="module" src="{src}" crossorigin {integrity}/>"#
            )),
            FileType::Woff | FileType::Woff2 => None,
        }
    }
}

impl Manifest {
    /// Render an `index.html` page
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid.
    pub fn render<'a>(
        &'a self,
        assets_base: &Utf8Path,
        config: &impl serde::Serialize,
    ) -> Result<String, InvalidManifest<'a>> {
        let entrypoint = Utf8Path::new("index.html");

        let entry = self.lookup_by_name(entrypoint)?;
        let main_asset = Asset::new(entry)?;
        // XXX: there might be a way to do this without allocating, but it's not worth
        // the effort
        let all_assets = entry
            .css
            .iter()
            .flatten()
            .map(|name| self.lookup_by_file(name).and_then(Asset::new))
            .chain(std::iter::once(Ok(main_asset)))
            .collect::<Result<BTreeSet<_>, _>>()?;

        // Find the items that should be pre-loaded
        let preload = self.find_preload(entry)?;
        let head = preload
            .iter()
            .filter(|p| {
                // We don't preload woff files, because they have woff2 alternatives, which will
                // most likely be used
                p.file_type != FileType::Woff
            })
            .map(|p| p.preload_tag(assets_base))
            .chain(all_assets.iter().filter_map(|p| p.include_tag(assets_base)));

        let html = template(head, config);

        Ok(html)
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
