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

use tera::{helpers::tests::number_args_allowed, Tera, Value};
use url::Url;

pub fn register(tera: &mut Tera) {
    tera.register_tester("empty", self::tester_empty);
    tera.register_function("add_params_to_uri", function_add_params_to_uri);
    tera.register_function("merge", function_merge);
    tera.register_function("dict", function_dict);
}

fn tester_empty(value: Option<&Value>, params: &[Value]) -> Result<bool, tera::Error> {
    number_args_allowed("empty", 0, params.len())?;

    match value.and_then(Value::as_array).map(|v| &v[..]) {
        Some(&[]) | None => Ok(true),
        Some(_) => Ok(false),
    }
}

enum ParamsWhere {
    Fragment,
    Query,
}

fn function_add_params_to_uri(params: &HashMap<String, Value>) -> Result<Value, tera::Error> {
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
    let params: HashMap<&String, &Value> = params
        .iter()
        // Filter out the `uri` and `mode` params
        .filter(|(k, _v)| k != &"uri" && k != &"mode")
        .chain(existing.iter())
        .collect();

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
            .ok_or_else(|| tera::Error::msg(format!("Parameter {:?} should be an object", k)))?;
        ret.extend(v.clone());
    }

    Ok(Value::Object(ret))
}

#[allow(clippy::unnecessary_wraps)]
fn function_dict(params: &HashMap<String, Value>) -> Result<Value, tera::Error> {
    let ret = params.clone().into_iter().collect();
    Ok(Value::Object(ret))
}
