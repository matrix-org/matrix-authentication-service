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

use camino::Utf8PathBuf;
use clap::Parser;
use key::Context;
use mas_i18n::translations::TranslationTree;

mod key;
mod minijinja;

/// Scan a directory of templates for usage of the translation function and
/// output a translation tree.
#[derive(Parser)]
struct Options {
    /// The directory containing the templates
    templates: Utf8PathBuf,

    /// Path of the existing translation file
    existing: Option<Utf8PathBuf>,

    /// The extensions of the templates
    #[clap(long, default_value = "html,txt,subject")]
    extensions: String,

    /// The name of the translation function
    #[clap(long, default_value = "_")]
    function: String,
}

fn main() {
    tracing_subscriber::fmt::init();

    let options = Options::parse();

    // Open the existing translation file if one was provided
    let mut tree = if let Some(path) = options.existing {
        let mut file = File::open(path).expect("Failed to open existing translation file");
        serde_json::from_reader(&mut file).expect("Failed to parse existing translation file")
    } else {
        TranslationTree::default()
    };

    let mut context = Context::new(options.function);

    for entry in walkdir::WalkDir::new(&options.templates) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }

        let path: Utf8PathBuf = entry.into_path().try_into().expect("Non-UTF8 path");
        let relative = path.strip_prefix(&options.templates).expect("Invalid path");

        let Some(extension) = path.extension() else {
            continue;
        };

        if options.extensions.split(',').any(|e| e == extension) {
            tracing::debug!("Parsing {relative}");
            let template = std::fs::read_to_string(&path).expect("Failed to read template");
            match minijinja::parse(&template, relative.as_str()) {
                Ok(ast) => {
                    minijinja::find_in_stmt(&mut context, &ast).unwrap();
                }
                Err(err) => {
                    tracing::error!("Failed to parse {relative}: {}", err);
                }
            }
        }
    }

    context.add_missing(&mut tree);

    serde_json::to_writer_pretty(std::io::stdout(), &tree)
        .expect("Failed to write translation tree");

    // Just to make sure we don't end up with a trailing newline
    println!();
}
