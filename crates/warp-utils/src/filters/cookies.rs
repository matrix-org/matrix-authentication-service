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

//! Deal with encrypted cookies

use std::{convert::Infallible, marker::PhantomData};

use cookie::{Cookie, SameSite};
use data_encoding::BASE64URL_NOPAD;
use headers::{Header, HeaderValue, SetCookie};
use mas_config::Encrypter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use warp::{
    reject::{InvalidHeader, MissingCookie, Reject},
    Filter, Rejection, Reply,
};

use super::none_on_error;
use crate::{
    errors::WrapError,
    reply::{with_typed_header, WithTypedHeader},
};

/// Unable to decrypt the cookie
#[derive(Debug, Error)]
pub struct CookieDecryptionError<T: EncryptableCookieValue>(
    #[source] anyhow::Error,
    // This [`std::marker::PhantomData`] records what kind of cookie it was trying to save.
    // This then use when displaying the error.
    PhantomData<T>,
);

impl<T> Reject for CookieDecryptionError<T> where T: EncryptableCookieValue + 'static {}

impl<T: EncryptableCookieValue> From<anyhow::Error> for CookieDecryptionError<T> {
    fn from(e: anyhow::Error) -> Self {
        Self(e, PhantomData)
    }
}

impl<T: EncryptableCookieValue> std::fmt::Display for CookieDecryptionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to decrypt cookie {}", T::cookie_key())
    }
}

fn decryption_error<T>(e: anyhow::Error) -> Rejection
where
    T: EncryptableCookieValue + 'static,
{
    let e: CookieDecryptionError<T> = e.into();
    warp::reject::custom(e)
}

#[derive(Serialize, Deserialize)]
struct EncryptedCookie {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedCookie {
    /// Encrypt from a given key
    fn encrypt<T: Serialize>(payload: T, encrypter: &Encrypter) -> anyhow::Result<Self> {
        let message = bincode::serialize(&payload)?;
        let nonce: [u8; 12] = rand::random();
        let ciphertext = encrypter.encrypt(&nonce, &message)?;
        Ok(Self { nonce, ciphertext })
    }

    /// Decrypt the content of the cookie from a given key
    fn decrypt<T: DeserializeOwned>(&self, encrypter: &Encrypter) -> anyhow::Result<T> {
        let message = encrypter.decrypt(&self.nonce, &self.ciphertext)?;
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

/// Extract an optional encrypted cookie
#[must_use]
pub fn maybe_encrypted<T>(
    encrypter: &Encrypter,
) -> impl Filter<Extract = (Option<T>,), Error = Rejection> + Clone + Send + Sync + 'static
where
    T: DeserializeOwned + EncryptableCookieValue + 'static,
{
    encrypted(encrypter)
        .map(Some)
        .recover(none_on_error::<T, InvalidHeader>)
        .unify()
        .recover(none_on_error::<T, MissingCookie>)
        .unify()
        .recover(none_on_error::<T, CookieDecryptionError<T>>)
        .unify()
}

/// Extract an encrypted cookie
///
/// # Rejections
///
/// This can reject with either a [`warp::reject::MissingCookie`] or a
/// [`CookieDecryptionError`]
#[must_use]
pub fn encrypted<T>(
    encrypter: &Encrypter,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static
where
    T: DeserializeOwned + EncryptableCookieValue + 'static,
{
    let encrypter = encrypter.clone();
    warp::cookie::cookie(T::cookie_key()).and_then(move |value: String| {
        let encrypter = encrypter.clone();
        async move {
            let encrypted_payload =
                EncryptedCookie::from_cookie_value(&value).map_err(decryption_error::<T>)?;
            let decrypted_payload = encrypted_payload
                .decrypt(&encrypter)
                .map_err(decryption_error::<T>)?;
            Ok::<_, Rejection>(decrypted_payload)
        }
    })
}

/// Get an [`EncryptedCookieSaver`] to help saving an [`EncryptableCookieValue`]
#[must_use]
pub fn encrypted_cookie_saver(
    encrypter: &Encrypter,
) -> impl Filter<Extract = (EncryptedCookieSaver,), Error = Infallible> + Clone + Send + Sync + 'static
{
    let encrypter = encrypter.clone();
    warp::any().map(move || EncryptedCookieSaver {
        encrypter: encrypter.clone(),
    })
}

/// A cookie that can be encrypted with a well-known cookie key
pub trait EncryptableCookieValue: Serialize + Send + Sync + std::fmt::Debug {
    /// What key should be used for this cookie
    fn cookie_key() -> &'static str;
}

/// An opaque structure which helps encrypting a cookie and attach it to a reply
pub struct EncryptedCookieSaver {
    encrypter: Encrypter,
}

impl EncryptedCookieSaver {
    /// Save an [`EncryptableCookieValue`]
    pub fn save_encrypted<T: EncryptableCookieValue, R: Reply>(
        &self,
        cookie: &T,
        reply: R,
    ) -> Result<WithTypedHeader<R, SetCookie>, Rejection> {
        let encrypted = EncryptedCookie::encrypt(cookie, &self.encrypter)
            .wrap_error()?
            .to_cookie_value()
            .wrap_error()?;

        // TODO: make those options customizable
        let value = Cookie::build(T::cookie_key(), encrypted)
            .http_only(true)
            .same_site(SameSite::Lax)
            .finish()
            .to_string();

        let header = SetCookie::decode(&mut [HeaderValue::from_str(&value).wrap_error()?].iter())
            .wrap_error()?;
        Ok(with_typed_header(header, reply))
    }
}
