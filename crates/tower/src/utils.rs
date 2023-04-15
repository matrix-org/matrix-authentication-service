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

use opentelemetry::{KeyValue, Value};

/// A simple static key-value pair.
#[derive(Clone, Debug)]
pub struct KV<V>(pub &'static str, pub V);

impl<V> From<KV<V>> for KeyValue
where
    V: Into<Value>,
{
    fn from(value: KV<V>) -> Self {
        Self::new(value.0, value.1.into())
    }
}

/// A wrapper around a function that can be used to generate a key-value pair,
/// make or enrich spans.
#[derive(Clone, Debug)]
pub struct FnWrapper<F>(pub F);
