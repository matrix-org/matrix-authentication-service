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

use std::{collections::HashMap, sync::Arc};

use base64ct::{Base64, Encoding};
use minijinja::{Environment, Error, ErrorKind, Value};

fn split(value: &str, separator: Option<&str>) -> Vec<String> {
    value
        .split(separator.unwrap_or(" "))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>()
}

fn b64decode(value: &str) -> Result<Value, Error> {
    let bytes = Base64::decode_vec(value).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Failed to decode base64 string",
        )
        .with_source(e)
    })?;

    // It is not obvious, but the cleanest way to get a Value stored as raw bytes is
    // to wrap it in an Arc, because Value implements From<Arc<Vec<u8>>>
    Ok(Value::from(Arc::new(bytes)))
}

fn b64encode(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decode a Tag-Length-Value encoded byte array into a map of tag to value.
fn tlvdecode(bytes: &[u8]) -> Result<HashMap<Value, Value>, Error> {
    let mut iter = bytes.iter().copied();
    let mut ret = HashMap::new();
    loop {
        // TODO: this assumes the tag and the length are both single bytes, which is not
        // always the case with protobufs. We should properly decode varints
        // here.
        let Some(tag) = iter.next() else {
            break;
        };

        let len = iter
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "Invalid ILV encoding"))?;

        let mut bytes = Vec::with_capacity(len.into());
        for _ in 0..len {
            bytes.push(
                iter.next().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidOperation, "Invalid ILV encoding")
                })?,
            );
        }

        ret.insert(tag.into(), Value::from(Arc::new(bytes)));
    }

    Ok(ret)
}

fn string(value: &Value) -> String {
    value.to_string()
}

pub fn environment() -> Environment<'static> {
    let mut env = Environment::new();

    env.add_filter("split", split);
    env.add_filter("b64decode", b64decode);
    env.add_filter("b64encode", b64encode);
    env.add_filter("tlvdecode", tlvdecode);
    env.add_filter("string", string);

    env
}

#[cfg(test)]
mod tests {
    use super::environment;

    #[test]
    fn test_split() {
        let env = environment();
        let res = env
            .render_str(r#"{{ 'foo, bar' | split(', ') | join(" | ") }}"#, ())
            .unwrap();
        assert_eq!(res, "foo | bar");
    }

    #[test]
    fn test_ilvdecode() {
        let env = environment();
        let res = env
            .render_str(
                r#"
                    {%- set tlv = 'Cg0wLTM4NS0yODA4OS0wEgRtb2Nr' | b64decode | tlvdecode -%}
                    {%- if tlv[18]|string != 'mock' -%}
                        {{ "FAIL"/0 }}
                    {%- endif -%}
                    {{- tlv[10]|string -}}
                "#,
                (),
            )
            .unwrap();
        assert_eq!(res, "0-385-28089-0");
    }
}
