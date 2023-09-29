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

#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::fs::File;

use ::tera::Tera;
use camino::Utf8PathBuf;
use clap::Parser;
use key::add_missing;
use mas_i18n::translations::TranslationTree;

use crate::tera::find_keys;

mod key;
mod minijinja;
mod tera;

/// Scan a directory of templates for usage of the translation function and
/// output a translation tree.
#[derive(Parser)]
struct Options {
    /// The directory containing the templates
    templates: Utf8PathBuf,

    /// Path of the existing translation file
    existing: Option<Utf8PathBuf>,

    /// Whether to use minijinja instead of tera
    #[clap(long)]
    minijinja: bool,

    /// The name of the translation function
    #[clap(long, default_value = "t")]
    function: String,
}

fn main() {
    tracing_subscriber::fmt::init();

    let options = Options::parse();

    let mut tree = if let Some(path) = options.existing {
        let mut file = File::open(path).expect("Failed to open existing translation file");
        serde_json::from_reader(&mut file).expect("Failed to parse existing translation file")
    } else {
        TranslationTree::default()
    };

    let keys = if options.minijinja {
        let mut keys = Vec::new();
        for entry in walkdir::WalkDir::new(&options.templates) {
            let entry = entry.unwrap();
            let filename = entry.file_name().to_str().expect("Invalid filename");
            if entry.file_type().is_file()
                && (filename.ends_with(".html")
                    || filename.ends_with(".txt")
                    || filename.ends_with(".subject"))
            {
                let content = std::fs::read_to_string(entry.path()).unwrap();
                match minijinja::parse(&content, filename) {
                    Ok(ast) => {
                        keys.extend(minijinja::find_in_stmt(&ast).unwrap());
                    }
                    Err(err) => {
                        tracing::error!("Failed to parse {}: {}", entry.path().display(), err);
                    }
                }
            }
        }
        keys
    } else {
        let glob = format!("{base}/**/*.{{html,txt,subject}}", base = options.templates);
        tracing::debug!("Scanning templates in {}", glob);
        let tera = Tera::new(&glob).expect("Failed to load templates");

        find_keys(&tera, &options.function).unwrap()
    };
    add_missing(&mut tree, &keys);

    serde_json::to_writer_pretty(std::io::stdout(), &tree)
        .expect("Failed to write translation tree");

    // Just to make sure we don't end up with a trailing newline
    println!();
}
