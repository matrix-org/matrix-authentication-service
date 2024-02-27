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

use mas_i18n::{translations::TranslationTree, Message};
use minijinja::machinery::Span;

pub struct Context {
    keys: Vec<Key>,
    func: String,
    current_file: Option<String>,
}

impl Context {
    pub fn new(func: String) -> Self {
        Self {
            keys: Vec::new(),
            func,
            current_file: None,
        }
    }

    pub fn set_current_file(&mut self, file: &str) {
        self.current_file = Some(file.to_owned());
    }

    pub fn record(&mut self, key: Key) {
        self.keys.push(key);
    }

    pub fn func(&self) -> &str {
        &self.func
    }

    pub fn add_missing(&self, translation_tree: &mut TranslationTree) -> usize {
        let mut count = 0;
        for translatable in &self.keys {
            let message = Message::from_literal(String::new());

            let location = translatable.location.as_ref().map(|location| {
                if location.span.start_line == location.span.end_line {
                    format!(
                        "{}:{}:{}-{}",
                        location.file,
                        location.span.start_line,
                        location.span.start_col,
                        location.span.end_col
                    )
                } else {
                    format!(
                        "{}:{}:{}-{}:{}",
                        location.file,
                        location.span.start_line,
                        location.span.start_col,
                        location.span.end_line,
                        location.span.end_col
                    )
                }
            });

            let key = translatable
                .name
                .split('.')
                .chain(if translatable.kind == Kind::Plural {
                    Some("other")
                } else {
                    None
                });

            if translation_tree.set_if_not_defined(key, message, location) {
                count += 1;
            }
        }
        count
    }

    pub fn set_key_location(&self, mut key: Key, span: Span) -> Key {
        if let Some(file) = &self.current_file {
            key.location = Some(Location {
                file: file.clone(),
                span,
            });
        }

        key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Message,
    Plural,
}

#[derive(Debug, Clone)]
pub struct Location {
    file: String,
    span: Span,
}

#[derive(Debug, Clone)]
pub struct Key {
    kind: Kind,
    name: String,
    location: Option<Location>,
}

impl Key {
    pub fn new(kind: Kind, name: String) -> Self {
        Self {
            kind,
            name,
            location: None,
        }
    }
}
