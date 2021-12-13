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

use tera::{helpers::tests::number_args_allowed, Tera, Value};

pub fn register(tera: &mut Tera) {
    tera.register_tester("empty", self::tester_empty);
}

fn tester_empty(value: Option<&Value>, params: &[Value]) -> Result<bool, tera::Error> {
    number_args_allowed("empty", 0, params.len())?;

    match value.and_then(Value::as_array).map(|v| &v[..]) {
        Some(&[]) | None => Ok(true),
        Some(_) => Ok(false),
    }
}
