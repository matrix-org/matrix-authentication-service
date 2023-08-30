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

//! Additional functions, tests and filters used in templates

use std::{collections::HashMap, str::FromStr};

use camino::Utf8Path;
use mas_router::UrlBuilder;
use mas_spa::ViteManifest;
use tera::{helpers::tests::number_args_allowed, Tera, Value};
use url::Url;

pub fn register(tera: &mut Tera, url_builder: UrlBuilder, vite_manifest: ViteManifest) {
    tera.register_tester("empty", self::tester_empty);
    tera.register_filter("to_params", filter_to_params);
    tera.register_filter("safe_get", filter_safe_get);
    tera.register_filter("simplify_url", filter_simplify_url);
    tera.register_function("add_params_to_url", function_add_params_to_url);
    tera.register_function("merge", function_merge);
    tera.register_function("dict", function_dict);
    tera.register_function(
        "include_asset",
        IncludeAsset {
            url_builder,
            vite_manifest,
        },
    );
}

fn tester_empty(value: Option<&Value>, params: &[Value]) -> Result<bool, tera::Error> {
    number_args_allowed("empty", 0, params.len())?;

    match value.and_then(Value::as_array).map(|v| &v[..]) {
        Some(&[]) | None => Ok(true),
        Some(_) => Ok(false),
    }
}

fn filter_to_params(params: &Value, kv: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let prefix = kv.get("prefix").and_then(Value::as_str).unwrap_or("");
    let params = serde_urlencoded::to_string(params)
        .map_err(|e| tera::Error::chain(e, "Could not serialize parameters"))?;

    if params.is_empty() {
        Ok(Value::String(String::new()))
    } else {
        Ok(Value::String(format!("{prefix}{params}")))
    }
}

/// Alternative to `get` which does not crash on `None` and defaults to `None`
pub fn filter_safe_get(value: &Value, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let default = args.get("default").unwrap_or(&Value::Null);
    let key = args
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| tera::Error::msg("Invalid parameter `uri`"))?;

    match value.as_object() {
        Some(o) => match o.get(key) {
            Some(val) => Ok(val.clone()),
            // If the value is not present, allow for an optional default value
            None => Ok(default.clone()),
        },
        None => Ok(default.clone()),
    }
}

/// Filter which simplifies a URL to its domain name for HTTP(S) URLs
fn filter_simplify_url(value: &Value, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let url = value
        .as_str()
        .ok_or_else(|| tera::Error::msg("Invalid input for `simplify_url` filter"))?;

    if !args.is_empty() {
        return Err(tera::Error::msg("`simplify_url` filter takes no arguments"));
    }

    // Do nothing if the URL is not valid
    let Ok(mut url) = Url::from_str(url) else {
        return Ok(Value::String(url.to_owned()));
    };

    // Always at least remove the query parameters and fragment
    url.set_query(None);
    url.set_fragment(None);

    // Do nothing else for non-HTTPS URLs
    if url.scheme() != "https" {
        return Ok(Value::String(url.to_string()));
    }

    // Only return the domain name
    let Some(domain) = url.domain() else {
        return Ok(Value::String(url.to_string()));
    };

    Ok(Value::String(domain.to_owned()))
}

enum ParamsWhere {
    Fragment,
    Query,
}

fn function_add_params_to_url(params: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    use ParamsWhere::{Fragment, Query};

    // First, get the `uri`, `mode` and `params` parameters
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| tera::Error::msg("Invalid parameter `uri`"))?;
    let uri = Url::from_str(uri).map_err(|e| tera::Error::chain(uri, e))?;
    let mode = params
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| tera::Error::msg("Invalid parameter `mode`"))?;
    let mode = match mode {
        "fragment" => Fragment,
        "query" => Query,
        _ => return Err(tera::Error::msg("Invalid mode")),
    };
    let params = params
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| tera::Error::msg("Invalid parameter `params`"))?;

    // Get the relevant part of the URI and parse for existing parameters
    let existing = match mode {
        Fragment => uri.fragment(),
        Query => uri.query(),
    };
    let existing: HashMap<String, Value> = existing
        .map(serde_urlencoded::from_str)
        .transpose()
        .map_err(|e| tera::Error::chain(e, "Could not parse existing `uri` parameters"))?
        .unwrap_or_default();

    // Merge the exising and the additional parameters together
    let params: HashMap<&String, &Value> = params.iter().chain(existing.iter()).collect();

    // Transform them back to urlencoded
    let params = serde_urlencoded::to_string(params)
        .map_err(|e| tera::Error::chain(e, "Could not serialize back parameters"))?;

    let uri = {
        let mut uri = uri;
        match mode {
            Fragment => uri.set_fragment(Some(&params)),
            Query => uri.set_query(Some(&params)),
        };
        uri
    };

    Ok(Value::String(uri.to_string()))
}

fn function_merge(params: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let mut ret = serde_json::Map::new();
    for (k, v) in params {
        let v = v
            .as_object()
            .ok_or_else(|| tera::Error::msg(format!("Parameter {k:?} should be an object")))?;
        ret.extend(v.clone());
    }

    Ok(Value::Object(ret))
}

#[allow(clippy::unnecessary_wraps)]
fn function_dict(params: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let ret = params.clone().into_iter().collect();
    Ok(Value::Object(ret))
}

struct IncludeAsset {
    url_builder: UrlBuilder,
    vite_manifest: ViteManifest,
}

impl tera::Function for IncludeAsset {
    fn call(&self, args: &HashMap<String, Value>) -> tera::Result<Value> {
        let path = args.get("path").ok_or(tera::Error::msg(
            "Function `include_asset` was missing parameter `path`",
        ))?;
        let path: &Utf8Path = path
            .as_str()
            .ok_or_else(|| {
                tera::Error::msg(
                    "Function `include_asset` received an incorrect type for arg `path`",
                )
            })?
            .into();

        let assets = self.vite_manifest.assets_for(path).map_err(|e| {
            tera::Error::chain(
                "Invalid assets manifest while calling function `include_asset`",
                e.to_string(),
            )
        })?;

        let preloads = self.vite_manifest.preload_for(path).map_err(|e| {
            tera::Error::chain(
                "Invalid assets manifest while calling function `include_asset`",
                e.to_string(),
            )
        })?;

        let tags: Vec<String> = preloads
            .iter()
            .map(|asset| asset.preload_tag(self.url_builder.assets_base().into()))
            .chain(
                assets
                    .iter()
                    .filter_map(|asset| asset.include_tag(self.url_builder.assets_base().into())),
            )
            .collect();

        Ok(Value::String(tags.join("\n")))
    }

    fn is_safe(&self) -> bool {
        true
    }
}
