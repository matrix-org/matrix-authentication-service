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

use std::convert::Infallible;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaCha20Poly1305,
};
use cookie::Cookie;
use data_encoding::BASE64URL_NOPAD;
use headers::{Header, HeaderValue, SetCookie};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};

use super::headers::{typed_header, WithTypedHeader};
use crate::{config::CookiesConfig, errors::WrapError};

#[derive(Serialize, Deserialize)]
struct EncryptedCookie {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedCookie {
    /// Encrypt from a given key
    fn encrypt<T: Serialize>(payload: T, key: &[u8; 32]) -> anyhow::Result<Self> {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let message = bincode::serialize(&payload)?;
        let nonce: [u8; 12] = rand::random();
        let ciphertext = aead.encrypt(GenericArray::from_slice(&nonce[..]), &message[..])?;
        Ok(Self { nonce, ciphertext })
    }

    /// Decrypt the content of the cookie from a given key
    fn decrypt<T: DeserializeOwned>(&self, key: &[u8; 32]) -> anyhow::Result<T> {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let message = aead.decrypt(
            GenericArray::from_slice(&self.nonce[..]),
            &self.ciphertext[..],
        )?;
        let token = bincode::deserialize(&message)?;
        Ok(token)
    }

    /// Encode the encrypted cookie to be then saved as a cookie
    fn to_cookie_value(&self) -> anyhow::Result<String> {
        let raw = bincode::serialize(self)?;
        Ok(BASE64URL_NOPAD.encode(&raw))
    }

    fn from_cookie_value(value: &str) -> anyhow::Result<Self> {
        let raw = BASE64URL_NOPAD.decode(value.as_bytes())?;
        let content = bincode::deserialize(&raw)?;
        Ok(content)
    }
}

pub fn maybe_encrypted<T>(
    options: &CookiesConfig,
) -> impl Filter<Extract = (Option<T>,), Error = Infallible> + Clone + Send + Sync + 'static
where
    T: DeserializeOwned + EncryptableCookieValue + Send + 'static,
{
    let secret = options.secret;
    warp::cookie::optional(T::cookie_key()).map(move |maybe_value: Option<String>| {
        maybe_value
            .and_then(|value| EncryptedCookie::from_cookie_value(&value).ok())
            .and_then(|encrypted| encrypted.decrypt(&secret).ok())
    })
}

pub fn encrypted<T>(
    options: &CookiesConfig,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static
where
    T: DeserializeOwned + EncryptableCookieValue + Send + 'static,
{
    let secret = options.secret;
    warp::cookie::cookie(T::cookie_key()).and_then(move |value: String| async move {
        let encrypted = EncryptedCookie::from_cookie_value(&value).wrap_error()?;
        let decrypted = encrypted.decrypt(&secret).wrap_error()?;
        Ok::<_, Rejection>(decrypted)
    })
}

pub fn with_cookie_saver(
    options: &CookiesConfig,
) -> impl Filter<Extract = (EncryptedCookieSaver,), Error = Infallible> + Clone + Send + Sync + 'static
{
    let secret = options.secret;
    warp::any().map(move || EncryptedCookieSaver { secret })
}

/// A cookie that can be encrypted with a well-known cookie key
pub trait EncryptableCookieValue {
    fn cookie_key() -> &'static str;
}

pub struct EncryptedCookieSaver {
    secret: [u8; 32],
}

impl EncryptedCookieSaver {
    pub fn save_encrypted<T: Serialize + EncryptableCookieValue, R: Reply>(
        &self,
        cookie: &T,
        reply: R,
    ) -> Result<WithTypedHeader<R, SetCookie>, Rejection> {
        let encrypted = EncryptedCookie::encrypt(cookie, &self.secret)
            .wrap_error()?
            .to_cookie_value()
            .wrap_error()?;
        let value = Cookie::build(T::cookie_key(), encrypted)
            .finish()
            .to_string();
        let header = SetCookie::decode(&mut [HeaderValue::from_str(&value).wrap_error()?].iter())
            .wrap_error()?;
        Ok(typed_header(header, reply))
    }
}
