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
use data_encoding::BASE64URL_NOPAD;
use headers::SetCookie;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSeconds};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

use super::cookies::{save_encrypted, WithTypedHeader};
use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::WrapError,
};

#[serde_as]
#[derive(Serialize, Deserialize)]
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
    pub fn form_value(&self) -> String {
        BASE64URL_NOPAD.encode(&self.token[..])
    }

    /// Verifies that the value got from an HTML form matches this token
    pub fn verify_form_value(&self, form_value: &str) -> anyhow::Result<()> {
        let form_value = BASE64URL_NOPAD.decode(form_value.as_bytes())?;
        if self.token[..] == form_value {
            Ok(())
        } else {
            Err(anyhow::anyhow!("CSRF token mismatch"))
        }
    }

    fn verify_expiration(self) -> anyhow::Result<Self> {
        if Utc::now() < self.expiration {
            Ok(self)
        } else {
            Err(anyhow::anyhow!("CSRF token expired"))
        }
    }
}

pub fn csrf_token(cookies_config: &CookiesConfig) -> BoxedFilter<(CsrfToken,)> {
    super::cookies::encrypted("csrf", cookies_config)
        .and_then(move |token: CsrfToken| async move {
            let verified = token.verify_expiration().wrap_error()?;
            Ok::<_, Rejection>(verified)
        })
        .boxed()
}

pub fn updated_csrf_token(
    cookies_config: &CookiesConfig,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(CsrfToken,)> {
    let ttl = csrf_config.ttl;
    super::cookies::maybe_encrypted("csrf", cookies_config)
        .and_then(move |maybe_token: Option<CsrfToken>| async move {
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
        })
        .boxed()
}

pub fn save_csrf_token<R: Reply, F>(
    cookies_config: &CookiesConfig,
) -> impl Fn(F) -> BoxedFilter<(WithTypedHeader<R, SetCookie>,)>
where
    F: Filter<Extract = (CsrfToken, R), Error = Rejection> + Clone + Send + Sync + 'static,
{
    save_encrypted("csrf", cookies_config)
}
