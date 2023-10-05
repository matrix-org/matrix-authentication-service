// Copyright 2021 The Matrix.org Foundation C.I.C.
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

// This is needed to make the Environment::add* functions work
#![allow(clippy::needless_pass_by_value)]

//! Additional functions, tests and filters used in templates

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Formatter,
    str::FromStr,
    sync::Arc,
};

use camino::Utf8Path;
use mas_i18n::{sprintf::FormattedMessagePart, Argument, ArgumentList, DataLocale, Translator};
use mas_router::UrlBuilder;
use mas_spa::ViteManifest;
use minijinja::{
    escape_formatter,
    machinery::make_string_output,
    value::{from_args, Kwargs, Object, SeqObject, ViaDeserialize},
    Error, ErrorKind, State, Value,
};
use url::Url;

pub fn register(
    env: &mut minijinja::Environment,
    url_builder: UrlBuilder,
    vite_manifest: ViteManifest,
    translator: Arc<Translator>,
) {
    env.add_test("empty", self::tester_empty);
    env.add_test("starting_with", tester_starting_with);
    env.add_filter("to_params", filter_to_params);
    env.add_filter("simplify_url", filter_simplify_url);
    env.add_filter("add_slashes", filter_add_slashes);
    env.add_filter("split", filter_split);
    env.add_function("add_params_to_url", function_add_params_to_url);
    env.add_global(
        "include_asset",
        Value::from_object(IncludeAsset {
            url_builder,
            vite_manifest,
        }),
    );
    env.add_global(
        "translator",
        Value::from_object(TranslatorFunc { translator }),
    );
}

fn tester_empty(seq: &dyn SeqObject) -> bool {
    seq.item_count() == 0
}

fn tester_starting_with(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
}

fn filter_split(value: &str, separator: &str) -> Vec<String> {
    value
        .split(separator)
        .map(std::borrow::ToOwned::to_owned)
        .collect()
}

fn filter_add_slashes(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\'', "\\\'")
}

fn filter_to_params(params: &Value, kwargs: Kwargs) -> Result<String, Error> {
    let params = serde_urlencoded::to_string(params).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize parameters",
        )
        .with_source(e)
    })?;

    let prefix = kwargs.get("prefix").unwrap_or("");
    kwargs.assert_all_used()?;

    if params.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{prefix}{params}"))
    }
}

/// Filter which simplifies a URL to its domain name for HTTP(S) URLs
fn filter_simplify_url(url: &str) -> String {
    // Do nothing if the URL is not valid
    let Ok(mut url) = Url::from_str(url) else {
        return url.to_owned();
    };

    // Always at least remove the query parameters and fragment
    url.set_query(None);
    url.set_fragment(None);

    // Do nothing else for non-HTTPS URLs
    if url.scheme() != "https" {
        return url.to_string();
    }

    // Only return the domain name
    let Some(domain) = url.domain() else {
        return url.to_string();
    };

    domain.to_owned()
}

enum ParamsWhere {
    Fragment,
    Query,
}

fn function_add_params_to_url(
    uri: ViaDeserialize<Url>,
    mode: &str,
    params: ViaDeserialize<HashMap<String, Value>>,
) -> Result<String, Error> {
    use ParamsWhere::{Fragment, Query};

    let mode = match mode {
        "fragment" => Fragment,
        "query" => Query,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid `mode` parameter",
            ))
        }
    };

    // First, get the `uri`, `mode` and `params` parameters
    // Get the relevant part of the URI and parse for existing parameters
    let existing = match mode {
        Fragment => uri.fragment(),
        Query => uri.query(),
    };
    let existing: HashMap<String, Value> = existing
        .map(serde_urlencoded::from_str)
        .transpose()
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                "Could not parse existing `uri` parameters",
            )
            .with_source(e)
        })?
        .unwrap_or_default();

    // Merge the exising and the additional parameters together
    let params: HashMap<&String, &Value> = params.iter().chain(existing.iter()).collect();

    // Transform them back to urlencoded
    let params = serde_urlencoded::to_string(params).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize back parameters",
        )
        .with_source(e)
    })?;

    let uri = {
        let mut uri = uri;
        match mode {
            Fragment => uri.set_fragment(Some(&params)),
            Query => uri.set_query(Some(&params)),
        };
        uri
    };

    Ok(uri.to_string())
}

struct TranslatorFunc {
    translator: Arc<Translator>,
}

impl std::fmt::Debug for TranslatorFunc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslatorFunc")
            .field("translator", &"..")
            .finish()
    }
}

impl std::fmt::Display for TranslatorFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("translator")
    }
}

impl Object for TranslatorFunc {
    fn call(&self, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (lang,): (&str,) = from_args(args)?;

        let lang: DataLocale = lang.parse().map_err(|e| {
            Error::new(ErrorKind::InvalidOperation, "Invalid language").with_source(e)
        })?;

        Ok(Value::from_object(TranslateFunc {
            lang,
            translator: Arc::clone(&self.translator),
        }))
    }
}

struct TranslateFunc {
    translator: Arc<Translator>,
    lang: DataLocale,
}

impl std::fmt::Debug for TranslateFunc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Translate")
            .field("translator", &"..")
            .field("lang", &self.lang)
            .finish()
    }
}

impl std::fmt::Display for TranslateFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("translate")
    }
}

impl Object for TranslateFunc {
    fn call(&self, state: &State, args: &[Value]) -> Result<Value, Error> {
        let (key, kwargs): (&str, Kwargs) = from_args(args)?;

        let (message, _locale) = if let Some(count) = kwargs.get("count")? {
            self.translator
                .plural_with_fallback(self.lang.clone(), key, count)
                .ok_or(Error::new(
                    ErrorKind::InvalidOperation,
                    "Missing translation",
                ))?
        } else {
            self.translator
                .message_with_fallback(self.lang.clone(), key)
                .ok_or(Error::new(
                    ErrorKind::InvalidOperation,
                    "Missing translation",
                ))?
        };

        let res: Result<ArgumentList, Error> = kwargs
            .args()
            .map(|name| {
                let value: Value = kwargs.get(name)?;
                let value = serde_json::to_value(value).map_err(|e| {
                    Error::new(ErrorKind::InvalidOperation, "Could not serialize argument")
                        .with_source(e)
                })?;

                Ok::<_, Error>(Argument::named(name.to_owned(), value))
            })
            .collect();
        let list = res?;

        let formatted = message.format_(&list).map_err(|e| {
            Error::new(ErrorKind::InvalidOperation, "Could not format message").with_source(e)
        })?;

        let mut buf = String::with_capacity(formatted.len());
        let mut output = make_string_output(&mut buf);
        for part in formatted.parts() {
            match part {
                FormattedMessagePart::Text(text) => {
                    // Literal text, just write it
                    output.write_str(text)?;
                }
                FormattedMessagePart::Placeholder(placeholder) => {
                    // Placeholder, escape it
                    escape_formatter(&mut output, state, &placeholder.as_str().into())?;
                }
            }
        }

        Ok(Value::from_safe_string(buf))
    }
}

struct IncludeAsset {
    url_builder: UrlBuilder,
    vite_manifest: ViteManifest,
}

impl std::fmt::Debug for IncludeAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncludeAsset")
            .field("url_builder", &self.url_builder.assets_base())
            .field("vite_manifest", &"..")
            .finish()
    }
}

impl std::fmt::Display for IncludeAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("include_asset")
    }
}

impl Object for IncludeAsset {
    fn call(&self, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (path, kwargs): (&str, Kwargs) = from_args(args)?;

        let preload = kwargs.get("preload").unwrap_or(false);
        kwargs.assert_all_used()?;

        let path: &Utf8Path = path.into();

        let assets = self.vite_manifest.assets_for(path).map_err(|_e| {
            Error::new(
                ErrorKind::InvalidOperation,
                "Invalid assets manifest while calling function `include_asset`",
            )
        })?;

        let preloads = if preload {
            self.vite_manifest.preload_for(path).map_err(|_e| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    "Invalid assets manifest while calling function `include_asset`",
                )
            })?
        } else {
            BTreeSet::new()
        };

        let tags: Vec<String> = preloads
            .iter()
            .map(|asset| asset.preload_tag(self.url_builder.assets_base().into()))
            .chain(
                assets
                    .iter()
                    .filter_map(|asset| asset.include_tag(self.url_builder.assets_base().into())),
            )
            .collect();

        Ok(Value::from_safe_string(tags.join("\n")))
    }
}
