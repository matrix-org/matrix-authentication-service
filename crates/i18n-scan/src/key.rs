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

pub struct Context {
    keys: Vec<Key>,
    func: String,
}

impl Context {
    pub fn new(func: String) -> Self {
        Self {
            keys: Vec::new(),
            func,
        }
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
            let message = Message::from_literal(translatable.default_value());
            let key = translatable
                .key
                .split('.')
                .chain(if translatable.kind == Kind::Plural {
                    Some("other")
                } else {
                    None
                });

            if translation_tree.set_if_not_defined(key, message) {
                count += 1;
            }
        }
        count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Message,
    Plural,
}

#[derive(Debug, Clone)]
pub struct Key {
    kind: Kind,
    key: String,
}

impl Key {
    pub fn new(kind: Kind, key: String) -> Self {
        Self { kind, key }
    }

    pub fn default_value(&self) -> String {
        match self.kind {
            Kind::Message => self.key.clone(),
            Kind::Plural => format!("%(count)d {}", self.key),
        }
    }
}
