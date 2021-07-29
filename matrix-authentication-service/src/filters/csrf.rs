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

use std::time::SystemTime;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaCha20Poly1305,
};
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, CookieBuilder, SameSite};
use data_encoding::BASE64URL_NOPAD;
use headers::{Header, HeaderMapExt, HeaderValue, SetCookie};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSeconds};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

use crate::errors::WrapError;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct UnencryptedToken {
    #[serde_as(as = "TimestampSeconds<i64>")]
    expiration: DateTime<Utc>,
    token: [u8; 32],
}

impl UnencryptedToken {
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

    /// Encrypt the token with the given chacha20-poly1305 key
    fn encrypt(&self, key: &[u8; 32]) -> anyhow::Result<EncryptedToken> {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);

        // Serialize the token
        let message = bincode::serialize(self)?;

        // Generate a nonce
        let nonce: [u8; 12] = rand::random();

        // And encrypt everything
        let ciphertext = aead.encrypt(GenericArray::from_slice(&nonce[..]), &message[..])?;

        // Return the encrypted token + nonce
        Ok(EncryptedToken { nonce, ciphertext })
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

    fn to_cookie_builder<'c, 'n: 'c>(
        &self,
        name: &'n str,
        key: &[u8; 32],
    ) -> anyhow::Result<CookieBuilder<'c>> {
        // Converting expiration time from `chrono` to `time` via native `SystemTime`
        let expires: SystemTime = self.expiration.into();
        Ok(self
            .encrypt(key)?
            .to_cookie_builder(name)?
            .expires(Some(expires.into())))
    }

    fn from_cookie_value(value: &str, key: &[u8; 32]) -> anyhow::Result<Self> {
        let encrypted = EncryptedToken::from_cookie_value(value)?;
        let token = encrypted.decrypt(key)?;
        Ok(token)
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedToken {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedToken {
    /// Decrypt the content of the token from a given key
    fn decrypt(&self, key: &[u8; 32]) -> anyhow::Result<UnencryptedToken> {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let message = aead.decrypt(
            GenericArray::from_slice(&self.nonce[..]),
            &self.ciphertext[..],
        )?;
        let token = bincode::deserialize(&message)?;
        Ok(token)
    }

    /// Encode the token to be then saved as a cookie
    fn to_cookie_value(&self) -> anyhow::Result<String> {
        let raw = bincode::serialize(self)?;
        Ok(BASE64URL_NOPAD.encode(&raw))
    }

    /// Extract the encrypted token from a cookie
    fn from_cookie_value(value: &str) -> anyhow::Result<Self> {
        let raw = BASE64URL_NOPAD.decode(value.as_bytes())?;
        let content = bincode::deserialize(&raw)?;
        Ok(content)
    }

    fn to_cookie_builder<'c, 'n: 'c>(&self, name: &'n str) -> anyhow::Result<CookieBuilder<'c>> {
        let value = self.to_cookie_value()?;
        Ok(Cookie::build(name, value)
            .http_only(true)
            .same_site(SameSite::Strict))
    }
}

pub fn extract_or_generate(
    key: [u8; 32],
    cookie_name: &'static str,
    ttl: Duration,
) -> BoxedFilter<(UnencryptedToken,)> {
    warp::any()
        .map(move || (key, ttl))
        .untuple_one()
        .and(warp::cookie::optional(cookie_name))
        .and_then(|key, ttl, maybe_cookie: Option<String>| async move {
            // Explicitely specify the "Error" type here to have the `?` operation working
            Ok::<_, Rejection>(
                maybe_cookie
                    // Try decrypting the cookie
                    .map(|cookie| UnencryptedToken::from_cookie_value(&cookie, &key))
                    // If there was an error decrypting it, bail out here
                    .transpose()
                    .wrap_error()?
                    // Verify its TTL (but do not hard-error if it expired)
                    .and_then(|token| token.verify_expiration().ok())
                    .map_or_else(
                        // Generate a new token if no valid one were found
                        || UnencryptedToken::generate(ttl),
                        // Else, refresh the expiration of the token
                        |token| token.refresh(ttl),
                    ),
            )
        })
        .boxed()
}

pub struct WithTypedHeader<R, H> {
    reply: R,
    header: H,
}

impl<R, H> Reply for WithTypedHeader<R, H>
where
    R: Reply,
    H: Header + Send,
{
    fn into_response(self) -> warp::reply::Response {
        let mut res = self.reply.into_response();
        res.headers_mut().typed_insert(self.header);
        res
    }
}

pub fn with_csrf<R: Reply, F>(
    key: [u8; 32],
    cookie_name: &'static str,
) -> impl Fn(F) -> BoxedFilter<(WithTypedHeader<R, SetCookie>,)>
where
    F: Filter<Extract = (UnencryptedToken, R), Error = Rejection> + Clone + Send + Sync + 'static,
{
    move |f: F| {
        f.and_then(move |token: UnencryptedToken, reply: R| async move {
            let cookie = token
                .to_cookie_builder(cookie_name, &key)
                .wrap_error()?
                .finish()
                .to_string();
            let header =
                SetCookie::decode(&mut [HeaderValue::from_str(&cookie).wrap_error()?].iter())
                    .wrap_error()?;
            Ok::<_, Rejection>(WithTypedHeader { reply, header })
        })
        .boxed()
    }
}
