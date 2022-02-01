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

//! Stateless CSRF protection middleware based on a chacha20-poly1305 encrypted
//! and signed token

use chrono::{DateTime, Duration, Utc};
use data_encoding::{DecodeError, BASE64URL_NOPAD};
use mas_config::{CsrfConfig, Encrypter};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::{serde_as, TimestampSeconds};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection};

use super::cookies::EncryptableCookieValue;

/// Failed to validate CSRF token
#[derive(Debug, Error)]
pub enum CsrfError {
    /// The token in the form did not match the token in the cookie
    #[error("CSRF token mismatch")]
    Mismatch,

    /// The token expired
    #[error("CSRF token expired")]
    Expired,

    /// Failed to decode the token
    #[error("could not decode CSRF token")]
    Decode(#[from] DecodeError),
}

impl Reject for CsrfError {}

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
    fn new(token: [u8; 32], ttl: Duration) -> Self {
        let expiration = Utc::now() + ttl;
        Self { expiration, token }
    }

    /// Generate a new random token valid for a specified duration
    fn generate(ttl: Duration) -> Self {
        let token = rand::random();
        Self::new(token, ttl)
    }

    /// Generate a new token with the same value but an up to date expiration
    fn refresh(self, ttl: Duration) -> Self {
        Self::new(self.token, ttl)
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

    fn verify_expiration(self) -> Result<Self, CsrfError> {
        if Utc::now() < self.expiration {
            Ok(self)
        } else {
            Err(CsrfError::Expired)
        }
    }
}

impl EncryptableCookieValue for CsrfToken {
    fn cookie_key() -> &'static str {
        "csrf"
    }
}

/// A CSRF-protected form
#[derive(Deserialize)]
struct CsrfForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> CsrfForm<T> {
    fn verify_csrf(self, token: &CsrfToken) -> Result<T, CsrfError> {
        // Verify CSRF from request
        token.verify_form_value(&self.csrf)?;
        Ok(self.inner)
    }
}

fn csrf_token(
    encrypter: &Encrypter,
) -> impl Filter<Extract = (CsrfToken,), Error = Rejection> + Clone + Send + Sync + 'static {
    super::cookies::encrypted(encrypter).and_then(move |token: CsrfToken| async move {
        let verified = token.verify_expiration()?;
        Ok::<_, Rejection>(verified)
    })
}

/// Extract an up-to-date CSRF token to include in forms
///
/// Routes using this should not forget to reply the updated CSRF cookie using
/// an [`EncryptedCookieSaver`][`super::cookies::EncryptedCookieSaver`] obtained
/// with [`encrypted_cookie_saver`][`super::cookies::encrypted_cookie_saver`]
#[must_use]
pub fn updated_csrf_token(
    encrypter: &Encrypter,
    csrf_config: &CsrfConfig,
) -> impl Filter<Extract = (CsrfToken,), Error = Rejection> + Clone + Send + Sync + 'static {
    let ttl = csrf_config.ttl;
    super::cookies::maybe_encrypted(encrypter).and_then(
        move |maybe_token: Option<CsrfToken>| async move {
            // Explicitely specify the "Error" type here to have the `?` operation working
            Ok::<_, Rejection>(
                maybe_token
                    // Verify its TTL (but do not hard-error if it expired)
                    .and_then(|token| token.verify_expiration().ok())
                    .map_or_else(
                        // Generate a new token if no valid one were found
                        || CsrfToken::generate(ttl),
                        // Else, refresh the expiration of the token
                        |token| token.refresh(ttl),
                    ),
            )
        },
    )
}

/// Extract values from a CSRF-protected form
///
/// # Rejections
///
/// This can reject with:
///
///  - [`warp::filters::body::BodyDeserializeError`] if the overall form failed
///    to decode
///  - [`CsrfError`] if the CSRF token was invalid or expired
///  - [`warp::reject::MissingCookie`] if the CSRF cookie was missing
///  - [`super::cookies::CookieDecryptionError`] if the cookie failed to decrypt
///
///  TODO: we might want to unify the last three rejections in one
#[must_use]
pub fn protected_form<T>(
    encrypter: &Encrypter,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static
where
    T: DeserializeOwned + Send + 'static,
{
    csrf_token(encrypter).and(warp::body::form()).and_then(
        |csrf_token: CsrfToken, protected_form: CsrfForm<T>| async move {
            let form = protected_form.verify_csrf(&csrf_token)?;
            Ok::<_, Rejection>(form)
        },
    )
}
