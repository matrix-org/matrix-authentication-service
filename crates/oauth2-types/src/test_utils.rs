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

use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

#[track_caller]
pub(crate) fn assert_serde_json<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    got: &T,
    expected_value: serde_json::Value,
) {
    let got_value = serde_json::to_value(&got).expect("could not serialize object as JSON value");
    assert_eq!(got_value, expected_value);

    let expected: T = serde_json::from_value(expected_value)
        .expect("could not deserialize object from JSON value");
    assert_eq!(got, &expected);
}
