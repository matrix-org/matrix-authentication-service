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

use std::convert::Infallible;

use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    response::{IntoResponseParts, ResponseParts},
};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar, SameSite};
use http::request::Parts;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
#[error("could not decode cookie")]
pub enum CookieDecodeError {
    Deserialize(#[from] serde_json::Error),
}

/// Manages cookie options and encryption key
///
/// This is meant to be accessible through axum's state via the [`FromRef`]
/// trait
#[derive(Clone)]
pub struct CookieManager {
    options: CookieOption,
    key: Key,
}

impl CookieManager {
    #[must_use]
    pub const fn new(base_url: Url, key: Key) -> Self {
        let options = CookieOption::new(base_url);
        Self { options, key }
    }

    #[must_use]
    pub fn derive_from(base_url: Url, key: &[u8]) -> Self {
        let key = Key::derive_from(key);
        Self::new(base_url, key)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for CookieJar
where
    CookieManager: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookie_manager = CookieManager::from_ref(state);
        let inner = PrivateCookieJar::from_headers(&parts.headers, cookie_manager.key.clone());
        let options = cookie_manager.options.clone();

        Ok(CookieJar { inner, options })
    }
}

#[derive(Debug, Clone)]
struct CookieOption {
    base_url: Url,
}

impl CookieOption {
    const fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    fn secure(&self) -> bool {
        self.base_url.scheme() == "https"
    }

    fn path(&self) -> &str {
        self.base_url.path()
    }

    fn apply<'a>(&self, mut cookie: Cookie<'a>) -> Cookie<'a> {
        cookie.set_http_only(true);
        cookie.set_secure(self.secure());
        cookie.set_path(self.path().to_owned());
        cookie.set_same_site(SameSite::Lax);
        cookie
    }
}

/// A cookie jar which encrypts cookies & sets secure options
pub struct CookieJar {
    inner: PrivateCookieJar<Key>,
    options: CookieOption,
}

impl CookieJar {
    /// Save the given payload in a cookie
    ///
    /// If `permanent` is true, the cookie will be valid for 10 years
    ///
    /// # Panics
    ///
    /// Panics if the payload cannot be serialized
    #[must_use]
    pub fn save<T: Serialize>(mut self, key: &str, payload: &T, permanent: bool) -> Self {
        let serialized =
            serde_json::to_string(payload).expect("failed to serialize cookie payload");

        let cookie = Cookie::new(key.to_owned(), serialized);
        let mut cookie = self.options.apply(cookie);

        if permanent {
            // XXX: this should use a clock
            cookie.make_permanent();
        }

        self.inner = self.inner.add(cookie);

        self
    }

    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CookieDecodeError> {
        let Some(cookie) = self.inner.get(key) else {
            return Ok(None);
        };

        let decoded = serde_json::from_str(cookie.value())?;
        Ok(Some(decoded))
    }
}

impl IntoResponseParts for CookieJar {
    type Error = Infallible;

    fn into_response_parts(self, res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        self.inner.into_response_parts(res)
    }
}
