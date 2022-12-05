// Copyright 2022 The Matrix.org Foundation C.I.C.
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

//! Private (encrypted) cookie jar, based on axum-extra's cookie jar

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("could not decode cookie")]
pub enum CookieDecodeError {
    Deserialize(#[from] serde_json::Error),
}

pub trait CookieExt {
    fn decode<T>(&self) -> Result<T, CookieDecodeError>
    where
        T: DeserializeOwned;

    #[must_use]
    fn encode<T>(self, t: &T) -> Self
    where
        T: Serialize;
}

impl<'a> CookieExt for axum_extra::extract::cookie::Cookie<'a> {
    fn decode<T>(&self) -> Result<T, CookieDecodeError>
    where
        T: DeserializeOwned,
    {
        let decoded = serde_json::from_str(self.value())?;
        Ok(decoded)
    }

    fn encode<T>(mut self, t: &T) -> Self
    where
        T: Serialize,
    {
        let encoded = serde_json::to_string(t).unwrap();
        self.set_value(encoded);
        self
    }
}
