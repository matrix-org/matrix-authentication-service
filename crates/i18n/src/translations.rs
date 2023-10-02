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

use std::{collections::BTreeMap, ops::Deref};

use icu_plurals::PluralCategory;
use serde::{Deserialize, Serialize};

use crate::sprintf::Message;

fn plural_category_as_str(category: PluralCategory) -> &'static str {
    match category {
        PluralCategory::Zero => "zero",
        PluralCategory::One => "one",
        PluralCategory::Two => "two",
        PluralCategory::Few => "few",
        PluralCategory::Many => "many",
        PluralCategory::Other => "other",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TranslationTree {
    Message(Message),
    Children(BTreeMap<String, TranslationTree>),
}

impl Default for TranslationTree {
    fn default() -> Self {
        Self::Children(BTreeMap::new())
    }
}

impl TranslationTree {
    /// Get a message from the tree by key.
    ///
    /// Returns `None` if the requested key is not found.
    #[must_use]
    pub fn message(&self, key: &str) -> Option<&Message> {
        let keys = key.split('.');
        let node = self.walk_path(keys)?;
        let message = node.as_message()?;
        Some(message)
    }

    /// Get a pluralized message from the tree by key and plural category.
    ///
    /// If the key doesn't have plural variants, this will return the message
    /// itself. Returns the "other" category if the requested category is
    /// not found. Returns `None` if the requested key is not found.
    #[must_use]
    pub fn pluralize(&self, key: &str, category: PluralCategory) -> Option<&Message> {
        let keys = key.split('.');
        let node = self.walk_path(keys)?;

        let subtree = match node {
            TranslationTree::Message(message) => return Some(message),
            TranslationTree::Children(tree) => tree,
        };

        if let Some(node) = subtree.get(plural_category_as_str(category)) {
            let message = node.as_message()?;
            Some(message)
        } else {
            // Fallback to the "other" category
            let message = subtree.get("other")?.as_message()?;
            Some(message)
        }
    }

    #[doc(hidden)]
    pub fn set_if_not_defined<K: Deref<Target = str>, I: IntoIterator<Item = K>>(
        &mut self,
        path: I,
        value: Message,
    ) -> bool {
        let mut path = path.into_iter();
        let Some(next) = path.next() else {
            if let TranslationTree::Message(_) = self {
                return false;
            }

            *self = TranslationTree::Message(value);
            return true;
        };

        match self {
            TranslationTree::Message(_) => panic!("cannot set a value on a message node"),
            TranslationTree::Children(children) => children
                .entry(next.deref().to_owned())
                .or_default()
                .set_if_not_defined(path, value),
        }
    }

    fn walk_path<K: Deref<Target = str>, I: IntoIterator<Item = K>>(
        &self,
        path: I,
    ) -> Option<&TranslationTree> {
        let mut path = path.into_iter();
        let Some(next) = path.next() else {
            return Some(self);
        };

        match self {
            TranslationTree::Message(_) => None,
            TranslationTree::Children(tree) => {
                let child = tree.get(&*next)?;
                child.walk_path(path)
            }
        }
    }

    fn as_message(&self) -> Option<&Message> {
        match self {
            TranslationTree::Message(message) => Some(message),
            TranslationTree::Children(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprintf::{arg_list, ArgumentList};

    #[test]
    fn test_it_works() {
        let tree = serde_json::json!({
            "hello": "world",
            "damals": {
              "about_x_hours_ago": {
                "one":   "about one hour ago",
                "other": "about %(count)s hours ago"
              }
            }
        });

        let result: Result<TranslationTree, _> = serde_json::from_value(tree);
        assert!(result.is_ok());
        let tree = result.unwrap();
        let message = tree.message("hello");
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(message.format(&ArgumentList::default()).unwrap(), "world");

        let message = tree.message("damals.about_x_hours_ago.one");
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(message.format(&arg_list!()).unwrap(), "about one hour ago");

        let message = tree.pluralize("damals.about_x_hours_ago", PluralCategory::Other);
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(
            message.format(&arg_list!(count = 2)).unwrap(),
            "about 2 hours ago"
        );
    }
}
