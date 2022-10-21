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

use axum_extra::extract::cookie::{Cookie, PrivateCookieJar};
use chrono::{DateTime, Duration, Utc};
use data_encoding::{DecodeError, BASE64URL_NOPAD};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSeconds};
use thiserror::Error;

use crate::{cookies::CookieDecodeError, CookieExt};

/// Failed to validate CSRF token
#[derive(Debug, Error)]
pub enum CsrfError {
    /// The token in the form did not match the token in the cookie
    #[error("CSRF token mismatch")]
    Mismatch,

    /// The token in the form did not match the token in the cookie
    #[error("Missing CSRF cookie")]
    Missing,

    /// Failed to decode the token
    #[error("could not decode CSRF cookie")]
    DecodeCookie(#[from] CookieDecodeError),

    /// The token expired
    #[error("CSRF token expired")]
    Expired,

    /// Failed to decode the token
    #[error("could not decode CSRF token")]
    Decode(#[from] DecodeError),
}

/// A CSRF token
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct CsrfToken {
    #[serde_as(as = "TimestampSeconds<i64>")]
    expiration: DateTime<Utc>,
    token: [u8; 32],
}

impl CsrfToken {
    /// Create a new token from a defined value valid for a specified duration
    fn new(token: [u8; 32], now: DateTime<Utc>, ttl: Duration) -> Self {
        let expiration = now + ttl;
        Self { expiration, token }
    }

    /// Generate a new random token valid for a specified duration
    fn generate(now: DateTime<Utc>, mut rng: impl Rng, ttl: Duration) -> Self {
        let token = rng.gen();
        Self::new(token, now, ttl)
    }

    /// Generate a new token with the same value but an up to date expiration
    fn refresh(self, now: DateTime<Utc>, ttl: Duration) -> Self {
        Self::new(self.token, now, ttl)
    }

    /// Get the value to include in HTML forms
    #[must_use]
    pub fn form_value(&self) -> String {
        BASE64URL_NOPAD.encode(&self.token[..])
    }

    /// Verifies that the value got from an HTML form matches this token
    pub fn verify_form_value(&self, form_value: &str) -> Result<(), CsrfError> {
        let form_value = BASE64URL_NOPAD.decode(form_value.as_bytes())?;
        if self.token[..] == form_value {
            Ok(())
        } else {
            Err(CsrfError::Mismatch)
        }
    }

    fn verify_expiration(self, now: DateTime<Utc>) -> Result<Self, CsrfError> {
        if now < self.expiration {
            Ok(self)
        } else {
            Err(CsrfError::Expired)
        }
    }
}

// A CSRF-protected form
#[derive(Deserialize)]
pub struct ProtectedForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

pub trait CsrfExt {
    fn csrf_token(self) -> (CsrfToken, Self);
    fn verify_form<T>(&self, form: ProtectedForm<T>) -> Result<T, CsrfError>;
}

impl<K> CsrfExt for PrivateCookieJar<K> {
    fn csrf_token(self) -> (CsrfToken, Self) {
        let jar = self;
        let mut cookie = jar.get("csrf").unwrap_or_else(|| Cookie::new("csrf", ""));
        cookie.set_path("/");
        cookie.set_http_only(true);

        // XXX: the rng source and clock should come from somewhere else
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();
        #[allow(clippy::disallowed_methods)]
        let rng = thread_rng();

        let new_token = cookie
            .decode()
            .ok()
            .and_then(|token: CsrfToken| token.verify_expiration(now).ok())
            .unwrap_or_else(|| CsrfToken::generate(now, rng, Duration::hours(1)))
            .refresh(now, Duration::hours(1));

        let cookie = cookie.encode(&new_token);
        let jar = jar.add(cookie);
        (new_token, jar)
    }

    fn verify_form<T>(&self, form: ProtectedForm<T>) -> Result<T, CsrfError> {
        // XXX: the clock should come from somewhere else
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();

        let cookie = self.get("csrf").ok_or(CsrfError::Missing)?;
        let token: CsrfToken = cookie.decode()?;
        let token = token.verify_expiration(now)?;
        token.verify_form_value(&form.csrf)?;
        Ok(form.inner)
    }
}
