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

    #[allow(dead_code)]
    assets: Option<Vec<Utf8PathBuf>>,

    #[allow(dead_code)]
    is_entry: Option<bool>,

    #[allow(dead_code)]
    is_dynamic_entry: Option<bool>,

    #[allow(dead_code)]
    imports: Option<Vec<Utf8PathBuf>>,

    dynamic_imports: Option<Vec<Utf8PathBuf>>,
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
  <script>window.APP_CONFIG = {config};</script>
  <script>{dark_mode_script}</script>
{head}</head>
<body>
  <div id="root"></div>
</body>
</html>"#
    )
}

impl ManifestEntry {
    /// Get a list of items to insert in the `<head>`
    fn head<'a>(&'a self, assets_base: &'a Utf8Path) -> impl Iterator<Item = String> + 'a {
        let css = self.css.iter().flat_map(|css| {
            css.iter().map(|href| {
                let href = assets_base.join(href);
                format!(r#"<link rel="stylesheet" href="{href}" />"#)
            })
        });

        let script = assets_base.join(&self.file);
        let script = format!(r#"<script type="module" crossorigin src="{script}"></script>"#);

        css.chain(std::iter::once(script))
    }
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
}

impl FileType {
    fn from_name(name: &Utf8Path) -> Option<Self> {
        match name.extension() {
            Some("css") => Some(Self::Stylesheet),
            Some("js") => Some(Self::Script),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid Vite manifest")]
pub enum InvalidManifest {
    #[error("No index.html")]
    NoIndex,

    #[error("Can't find preloaded entry")]
    CantFindPreload,

    #[error("Invalid file type")]
    InvalidFileType,
}

/// Represents an entry which should be preloaded
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Preload<'name> {
    name: &'name Utf8Path,
    file_type: FileType,
}

impl<'a> Preload<'a> {
    /// Generate a `<link>` tag for this entry
    fn link(&self, assets_base: &Utf8Path) -> String {
        let href = assets_base.join(self.name);
        match self.file_type {
            FileType::Stylesheet => {
                format!(r#"<link rel="preload" href="{href}" as="style" />"#)
            }
            FileType::Script => format!(
                r#"<link rel="preload" href="{href}" as="script" crossorigin="anonymous" />"#
            ),
        }
    }
}

impl Manifest {
    /// Render an `index.html` page
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid.
    pub fn render(
        &self,
        assets_base: &Utf8Path,
        config: &impl serde::Serialize,
    ) -> Result<String, InvalidManifest> {
        let entrypoint = Utf8Path::new("index.html");
        let entry = self.inner.get(entrypoint).ok_or(InvalidManifest::NoIndex)?;

        // Find the items that should be pre-loaded
        let preload = self.find_preload(entrypoint)?;
        let head = preload
            .iter()
            .map(|p| p.link(assets_base))
            .chain(entry.head(assets_base));

        let html = template(head, config);

        Ok(html)
    }

    /// Find entries to preload
    fn find_preload<'a>(
        &'a self,
        entrypoint: &Utf8Path,
    ) -> Result<BTreeSet<Preload<'a>>, InvalidManifest> {
        // TODO: we're preoading the whole tree. We should instead guess which component
        // should be loaded based on the route.
        let mut entries = BTreeSet::new();
        self.find_preload_rec(entrypoint, &mut entries)?;
        Ok(entries)
    }

    fn find_preload_rec<'a>(
        &'a self,
        entrypoint: &Utf8Path,
        entries: &mut BTreeSet<Preload<'a>>,
    ) -> Result<(), InvalidManifest> {
        let entry = self
            .inner
            .get(entrypoint)
            .ok_or(InvalidManifest::CantFindPreload)?;
        let name = &entry.file;
        let file_type = FileType::from_name(name).ok_or(InvalidManifest::InvalidFileType)?;
        let preload = Preload { name, file_type };
        let inserted = entries.insert(preload);

        if inserted {
            if let Some(css) = &entry.css {
                let file_type = FileType::Stylesheet;
                for name in css {
                    let preload = Preload { name, file_type };
                    entries.insert(preload);
                }
            }

            if let Some(dynamic_imports) = &entry.dynamic_imports {
                for import in dynamic_imports {
                    self.find_preload_rec(import, entries)?;
                }
            }
        }

        Ok(())
    }
}
