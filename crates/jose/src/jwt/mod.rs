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

use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{SigningKeystore, VerifyingKeystore};

mod header;
mod raw;
mod signed;

pub use self::{header::JsonWebSignatureHeader, signed::Jwt};

#[derive(Debug, PartialEq, Eq)]
pub struct JsonWebTokenParts {
    payload: String,
    signature: Vec<u8>,
}

#[derive(Error, Debug)]
#[error("failed to decode JWT")]
pub enum JwtPartsDecodeError {
    #[error("no dots found in the JWT")]
    NoDots,

    #[error("could not decode signature")]
    SignatureEncoding {
        #[from]
        inner: base64ct::Error,
    },
}

impl FromStr for JsonWebTokenParts {
    type Err = JwtPartsDecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (payload, signature) = s.rsplit_once('.').ok_or(JwtPartsDecodeError::NoDots)?;
        let signature = Base64UrlUnpadded::decode_vec(signature)?;
        let payload = payload.to_owned();
        Ok(Self { payload, signature })
    }
}

#[derive(Error, Debug)]
#[error("failed to serialize JWT")]
pub enum JwtSerializeError {
    #[error("failed to serialize JWT header")]
    Header {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to serialize payload")]
    Payload {
        #[source]
        inner: serde_json::Error,
    },
}

#[derive(Error, Debug)]
#[error("failed to serialize JWT")]
pub enum JwtSignatureError {
    Serialize {
        #[from]
        inner: JwtSerializeError,
    },

    Sign {
        #[source]
        inner: anyhow::Error,
    },
}

pub struct DecodedJsonWebToken<T> {
    header: JsonWebSignatureHeader,
    payload: T,
}

impl<T> DecodedJsonWebToken<T>
where
    T: Serialize,
{
    fn serialize(&self) -> Result<String, JwtSerializeError> {
        let header = serde_json::to_vec(&self.header)
            .map_err(|inner| JwtSerializeError::Header { inner })?;
        let header = Base64UrlUnpadded::encode_string(&header);

        let payload = serde_json::to_vec(&self.payload)
            .map_err(|inner| JwtSerializeError::Payload { inner })?;
        let payload = Base64UrlUnpadded::encode_string(&payload);

        Ok(format!("{}.{}", header, payload))
    }

    pub async fn sign<S: SigningKeystore>(
        &self,
        store: &S,
    ) -> Result<JsonWebTokenParts, JwtSignatureError> {
        let payload = self.serialize()?;
        let signature = store
            .sign(&self.header, payload.as_bytes())
            .await
            .map_err(|inner| JwtSignatureError::Sign { inner })?;
        Ok(JsonWebTokenParts { payload, signature })
    }
}

impl<T> DecodedJsonWebToken<T> {
    pub fn new(header: JsonWebSignatureHeader, payload: T) -> Self {
        Self { header, payload }
    }

    pub fn claims(&self) -> &T {
        &self.payload
    }

    pub fn header(&self) -> &JsonWebSignatureHeader {
        &self.header
    }

    pub fn split(self) -> (JsonWebSignatureHeader, T) {
        (self.header, self.payload)
    }
}

impl<T> FromStr for DecodedJsonWebToken<T>
where
    T: DeserializeOwned,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (header, payload) = s
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid payload"))?;

        let header = Base64UrlUnpadded::decode_vec(header)?;
        let header = serde_json::from_slice(&header)?;
        let payload = Base64UrlUnpadded::decode_vec(payload)?;
        let payload = serde_json::from_slice(&payload)?;
        Ok(Self { header, payload })
    }
}

impl JsonWebTokenParts {
    pub fn decode<T: DeserializeOwned>(&self) -> anyhow::Result<DecodedJsonWebToken<T>> {
        let decoded = self.payload.parse()?;
        Ok(decoded)
    }

    pub fn verify<S: VerifyingKeystore>(
        &self,
        header: &JsonWebSignatureHeader,
        store: &S,
    ) -> S::Future {
        store.verify(header, self.payload.as_bytes(), &self.signature)
    }

    pub async fn decode_and_verify<T: DeserializeOwned, S: VerifyingKeystore>(
        &self,
        store: &S,
    ) -> anyhow::Result<DecodedJsonWebToken<T>>
    where
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        let decoded = self.decode()?;
        self.verify(&decoded.header, store).await?;
        Ok(decoded)
    }

    #[must_use]
    pub fn serialize(&self) -> String {
        let payload = &self.payload;
        let signature = Base64UrlUnpadded::encode_string(&self.signature);
        format!("{}.{}", payload, signature)
    }
}

#[cfg(test)]
mod tests {
    use mas_iana::jose::JsonWebSignatureAlg;

    use super::*;
    use crate::SharedSecret;

    #[tokio::test]
    async fn decode_hs256() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let jwt: JsonWebTokenParts = jwt.parse().unwrap();
        let secret = "your-256-bit-secret";
        let store = SharedSecret::new(&secret);
        let jwt: DecodedJsonWebToken<serde_json::Value> =
            jwt.decode_and_verify(&store).await.unwrap();

        assert_eq!(jwt.header.typ(), Some("JWT"));
        assert_eq!(jwt.header.alg(), JsonWebSignatureAlg::Hs256);
        assert_eq!(
            jwt.payload,
            serde_json::json!({
               "sub": "1234567890",
               "name": "John Doe",
               "iat": 1_516_239_022
            })
        );
    }
}
