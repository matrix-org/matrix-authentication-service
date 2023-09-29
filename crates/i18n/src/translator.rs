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

use std::{collections::HashMap, fs::File, str::FromStr};

use camino::{Utf8Path, Utf8PathBuf};
use icu_list::{ListError, ListFormatter, ListLength};
use icu_locid::{Locale, ParserError};
use icu_locid_transform::fallback::LocaleFallbacker;
use icu_plurals::{PluralRules, PluralsError};
use icu_provider::{
    data_key, fallback::LocaleFallbackConfig, DataError, DataErrorKind, DataKey, DataLocale,
    DataRequest, DataRequestMetadata,
};
use icu_provider_adapters::fallback::LocaleFallbackProvider;
use thiserror::Error;
use writeable::Writeable;

use crate::{sprintf::Message, translations::TranslationTree};

/// Fake data key for errors
const DATA_KEY: DataKey = data_key!("mas/translations@1");

/// Error type for loading translations
#[derive(Debug, Error)]
#[error("Failed to load translations")]
pub enum LoadError {
    Io(#[from] std::io::Error),
    Deserialize(#[from] serde_json::Error),
    InvalidLocale(#[from] ParserError),
    InvalidFileName(Utf8PathBuf),
}

/// A translator for a set of translations.
#[derive(Debug)]
pub struct Translator {
    translations: HashMap<DataLocale, TranslationTree>,
    plural_provider: LocaleFallbackProvider<icu_plurals::provider::Baked>,
    list_provider: LocaleFallbackProvider<icu_list::provider::Baked>,
    fallbacker: LocaleFallbacker,
}

impl Translator {
    /// Create a new translator from a set of translations.
    #[must_use]
    pub fn new(translations: HashMap<DataLocale, TranslationTree>) -> Self {
        let fallbacker = LocaleFallbacker::new().static_to_owned();
        let plural_provider = LocaleFallbackProvider::new_with_fallbacker(
            icu_plurals::provider::Baked,
            fallbacker.clone(),
        );
        let list_provider = LocaleFallbackProvider::new_with_fallbacker(
            icu_list::provider::Baked,
            fallbacker.clone(),
        );

        Self {
            translations,
            plural_provider,
            list_provider,
            fallbacker,
        }
    }

    /// Load a set of translations from a directory.
    ///
    /// The directory should contain one JSON file per locale, with the locale
    /// being the filename without the extension, e.g. `en-US.json`.
    ///
    /// # Parameters
    ///
    /// * `path` - The path to load from.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read, or if any of the files
    /// cannot be parsed.
    pub fn load_from_path(path: &Utf8Path) -> Result<Self, LoadError> {
        let mut translations = HashMap::new();

        let dir = path.read_dir_utf8()?;
        for entry in dir {
            let entry = entry?;
            let path = entry.into_path();
            let Some(name) = path.file_stem() else {
                return Err(LoadError::InvalidFileName(path));
            };

            let locale: Locale = Locale::from_str(name)?;

            let mut file = File::open(path)?;
            let content = serde_json::from_reader(&mut file)?;
            translations.insert(locale.into(), content);
        }

        Ok(Self::new(translations))
    }

    /// Get a message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    #[must_use]
    pub fn message_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
    ) -> Option<(&Message, DataLocale)> {
        let mut iter = self
            .fallbacker
            .for_config(LocaleFallbackConfig::default())
            .fallback_for(locale);

        loop {
            let locale = iter.get();

            if let Ok(message) = self.message(locale, key) {
                return Some((message, iter.take()));
            }

            // Stop if we hit the `und` locale
            if locale.is_und() {
                return None;
            }

            iter.step();
        }
    }

    /// Get a message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn message(&self, locale: &DataLocale, key: &str) -> Result<&Message, DataError> {
        let request = DataRequest {
            locale,
            metadata: DataRequestMetadata::default(),
        };

        let tree = self
            .translations
            .get(locale)
            .ok_or(DataErrorKind::MissingLocale.with_req(DATA_KEY, request))?;

        let message = tree
            .message(key)
            .ok_or(DataErrorKind::MissingDataKey.with_req(DATA_KEY, request))?;

        Ok(message)
    }

    /// Get a plural message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    #[must_use]
    pub fn plural_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
        count: usize,
    ) -> Option<(&Message, DataLocale)> {
        let mut iter = self
            .fallbacker
            .for_config(LocaleFallbackConfig::default())
            .fallback_for(locale);

        loop {
            let locale = iter.get();

            if let Ok(message) = self.plural(locale, key, count) {
                return Some((message, iter.take()));
            }

            // Stop if we hit the `und` locale
            if locale.is_und() {
                return None;
            }

            iter.step();
        }
    }

    /// Get a plural message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn plural(
        &self,
        locale: &DataLocale,
        key: &str,
        count: usize,
    ) -> Result<&Message, PluralsError> {
        let plurals = PluralRules::try_new_cardinal_unstable(&self.plural_provider, locale)?;
        let category = plurals.category_for(count);

        let request = DataRequest {
            locale,
            metadata: DataRequestMetadata::default(),
        };

        let tree = self
            .translations
            .get(locale)
            .ok_or(DataErrorKind::MissingLocale.with_req(DATA_KEY, request))?;

        let message = tree
            .pluralize(key, category)
            .ok_or(DataErrorKind::MissingDataKey.with_req(DATA_KEY, request))?;

        Ok(message)
    }

    /// Format a list of items with the "and" conjunction.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `items` - The items to format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn and_list<'a, W: Writeable + 'a, I: Iterator<Item = W> + Clone + 'a>(
        &'a self,
        locale: &DataLocale,
        items: I,
    ) -> Result<String, ListError> {
        let formatter = ListFormatter::try_new_and_with_length_unstable(
            &self.list_provider,
            locale,
            ListLength::Wide,
        )?;

        let list = formatter.format_to_string(items);
        Ok(list)
    }

    /// Format a list of items with the "or" conjunction.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `items` - The items to format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn or_list<'a, W: Writeable + 'a, I: Iterator<Item = W> + Clone + 'a>(
        &'a self,
        locale: &DataLocale,
        items: I,
    ) -> Result<String, ListError> {
        let formatter = ListFormatter::try_new_or_with_length_unstable(
            &self.list_provider,
            locale,
            ListLength::Wide,
        )?;

        let list = formatter.format_to_string(items);
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use icu_locid::locale;

    use crate::{sprintf::arg_list, translator::Translator};

    fn translator() -> Translator {
        let root: Utf8PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
        let test_data = root.join("test_data");
        Translator::load_from_path(&test_data).unwrap()
    }

    #[test]
    fn test_message() {
        let translator = translator();

        let message = translator.message(&locale!("en").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hello!");

        let message = translator.message(&locale!("fr").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Bonjour !");

        let message = translator
            .message(&locale!("en-US").into(), "hello")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hey!");

        // Try the fallback chain
        let result = translator.message(&locale!("en-US").into(), "goodbye");
        assert!(result.is_err());

        let (message, locale) = translator
            .message_with_fallback(locale!("en-US").into(), "goodbye")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Goodbye!");
        assert_eq!(locale, locale!("en").into());
    }

    #[test]
    fn test_plurals() {
        let translator = translator();

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 active sessions.");

        // In english, zero is plural
        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 active sessions.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 session active.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 sessions actives.");

        // In french, zero is singular
        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 session active.");

        // Try the fallback chain
        let result = translator.plural(&locale!("en-US").into(), "active_sessions", 1);
        assert!(result.is_err());

        let (message, locale) = translator
            .plural_with_fallback(locale!("en-US").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");
        assert_eq!(locale, locale!("en").into());
    }

    #[test]
    fn test_list() {
        let translator = translator();

        let list = translator
            .and_list(&locale!("en").into(), ["one", "two", "three"].iter())
            .unwrap();
        assert_eq!(list, "one, two, and three");

        let list = translator
            .and_list(&locale!("fr").into(), ["un", "deux", "trois"].iter())
            .unwrap();
        assert_eq!(list, "un, deux et trois");

        let list = translator
            .or_list(&locale!("en").into(), ["one", "two", "three"].iter())
            .unwrap();
        assert_eq!(list, "one, two, or three");

        let list = translator
            .or_list(&locale!("fr").into(), ["un", "deux", "trois"].iter())
            .unwrap();
        assert_eq!(list, "un, deux ou trois");
    }
}
