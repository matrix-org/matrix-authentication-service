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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Message,
    Plural,
}

#[derive(Debug, Clone)]
pub struct Key {
    kind: KeyKind,
    key: String,
}

impl Key {
    pub fn new(kind: KeyKind, key: String) -> Self {
        Self { kind, key }
    }

    pub fn default_value(&self) -> String {
        match self.kind {
            KeyKind::Message => self.key.clone(),
            KeyKind::Plural => format!("%(count)d {}", self.key),
        }
    }
}

pub fn add_missing(translation_tree: &mut TranslationTree, keys: &[Key]) {
    for translatable in keys {
        let message = Message::from_literal(translatable.default_value());
        let key = translatable
            .key
            .split('.')
            .chain(if translatable.kind == KeyKind::Plural {
                Some("other")
            } else {
                None
            });

        translation_tree.set_if_not_defined(key, message);
    }
}
