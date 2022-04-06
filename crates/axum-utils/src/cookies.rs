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

use std::{convert::Infallible, marker::PhantomData};

use async_trait::async_trait;
use axum::{
    extract::{Extension, FromRequest, RequestParts},
    response::IntoResponseParts,
};
pub use cookie::Cookie;
use data_encoding::BASE64URL_NOPAD;
use headers::HeaderMap;
use http::header::{COOKIE, SET_COOKIE};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

pub struct PrivateCookieJar<K = cookie::Key> {
    jar: cookie::CookieJar,
    key: cookie::Key,
    _marker: PhantomData<K>,
}

impl<K> PrivateCookieJar<K> {
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        self.private_jar().get(name)
    }

    #[must_use]
    pub fn remove(mut self, cookie: Cookie<'static>) -> Self {
        self.private_jar_mut().remove(cookie);
        self
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, cookie: Cookie<'static>) -> Self {
        self.private_jar_mut().add(cookie);
        self
    }

    pub fn decrypt(&self, cookie: Cookie<'static>) -> Option<Cookie<'static>> {
        self.private_jar().decrypt(cookie)
    }

    fn private_jar(&self) -> cookie::PrivateJar<&'_ cookie::CookieJar> {
        self.jar.private(&self.key)
    }

    fn private_jar_mut(&mut self) -> cookie::PrivateJar<&'_ mut cookie::CookieJar> {
        self.jar.private_mut(&self.key)
    }

    pub fn set_cookies(self, headers: &mut HeaderMap) {
        for cookie in self.jar.delta() {
            if let Ok(header_value) = cookie.encoded().to_string().parse() {
                headers.append(SET_COOKIE, header_value);
            }
        }
    }
}

#[async_trait]
impl<B, K> FromRequest<B> for PrivateCookieJar<K>
where
    B: Send,
    K: Into<cookie::Key> + Clone + Send + Sync + 'static,
{
    type Rejection = <Extension<K> as FromRequest<B>>::Rejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(key): Extension<K> = Extension::from_request(req).await?;
        let key = key.into();

        let mut jar = cookie::CookieJar::new();
        let mut private_jar = jar.private_mut(&key);

        let cookies = req
            .headers()
            .get_all(COOKIE)
            .into_iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|cookie| Cookie::parse_encoded(cookie.to_owned()).ok());

        for cookie in cookies {
            if let Some(cookie) = private_jar.decrypt(cookie) {
                private_jar.add_original(cookie);
            }
        }

        Ok(Self {
            jar,
            key,
            _marker: PhantomData,
        })
    }
}

impl<K> IntoResponseParts for PrivateCookieJar<K> {
    type Error = Infallible;
    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.set_cookies(res.headers_mut());
        Ok(res)
    }
}

#[derive(Debug, Error)]
#[error("could not decode cookie")]
pub enum CookieDecodeError {
    Deserialize(#[from] bincode::Error),
    Decode(#[from] data_encoding::DecodeError),
}

pub trait CookieExt {
    fn decode<T>(&self) -> Result<T, CookieDecodeError>
    where
        T: DeserializeOwned;

    fn encode<T>(self, t: &T) -> Self
    where
        T: Serialize;
}

impl<'a> CookieExt for Cookie<'a> {
    fn decode<T>(&self) -> Result<T, CookieDecodeError>
    where
        T: DeserializeOwned,
    {
        let bytes = BASE64URL_NOPAD.decode(self.value().as_bytes())?;

        let decoded = bincode::deserialize(&bytes)?;

        Ok(decoded)
    }

    fn encode<T>(mut self, t: &T) -> Self
    where
        T: Serialize,
    {
        let bytes = bincode::serialize(t).unwrap();
        let encoded = BASE64URL_NOPAD.encode(&bytes);
        self.set_value(encoded);
        self
    }
}
