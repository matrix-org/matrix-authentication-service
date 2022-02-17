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
use mas_iana::jose::{
    JsonWebEncryptionCompressionAlgorithm, JsonWebEncryptionEnc, JsonWebSignatureAlg,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::{
    base64::{Base64, Standard, UrlSafe},
    formats::{Padded, Unpadded},
    serde_as, skip_serializing_none,
};
use url::Url;

use crate::{jwk::JsonWebKey, SigningKeystore, VerifyingKeystore};

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtHeader {
    alg: JsonWebSignatureAlg,

    #[serde(default)]
    enc: Option<JsonWebEncryptionEnc>,

    #[serde(default)]
    jku: Option<Url>,

    #[serde(default)]
    jwk: Option<JsonWebKey>,

    #[serde(default)]
    kid: Option<String>,

    #[serde(default)]
    x5u: Option<Url>,

    #[serde(default)]
    #[serde_as(as = "Option<Vec<Base64<Standard, Padded>>>")]
    x5c: Option<Vec<Vec<u8>>>,

    #[serde(default)]
    #[serde_as(as = "Option<Base64<UrlSafe, Unpadded>>")]
    x5t: Option<Vec<u8>>,
    #[serde(default, rename = "x5t#S256")]
    #[serde_as(as = "Option<Base64<UrlSafe, Unpadded>>")]
    x5t_s256: Option<Vec<u8>>,

    #[serde(default)]
    typ: Option<String>,

    #[serde(default)]
    cty: Option<String>,

    #[serde(default)]
    crit: Option<Vec<String>>,

    #[serde(default)]
    zip: Option<JsonWebEncryptionCompressionAlgorithm>,
}

impl JwtHeader {
    pub fn encode(&self) -> anyhow::Result<String> {
        let payload = serde_json::to_string(self)?;
        let encoded = Base64UrlUnpadded::encode_string(payload.as_bytes());
        Ok(encoded)
    }

    #[must_use]
    pub fn new(alg: JsonWebSignatureAlg) -> Self {
        Self {
            alg,
            enc: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            typ: None,
            cty: None,
            crit: None,
            zip: None,
        }
    }

    #[must_use]
    pub fn alg(&self) -> JsonWebSignatureAlg {
        self.alg
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

impl FromStr for JwtHeader {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = Base64UrlUnpadded::decode_vec(s)?;
        let parsed = serde_json::from_slice(&decoded)?;
        Ok(parsed)
    }
}

#[derive(Debug)]
pub struct JsonWebTokenParts {
    payload: String,
    signature: Vec<u8>,
}

impl FromStr for JsonWebTokenParts {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (payload, signature) = s
            .rsplit_once('.')
            .ok_or_else(|| anyhow::anyhow!("no dots found in JWT"))?;
        let signature = Base64UrlUnpadded::decode_vec(signature)?;
        let payload = payload.to_owned();
        Ok(Self { payload, signature })
    }
}

pub struct DecodedJsonWebToken<T> {
    header: JwtHeader,
    payload: T,
}

impl<T> DecodedJsonWebToken<T>
where
    T: Serialize,
{
    fn serialize(&self) -> anyhow::Result<String> {
        let header = serde_json::to_vec(&self.header)?;
        let header = Base64UrlUnpadded::encode_string(&header);
        let payload = serde_json::to_vec(&self.payload)?;
        let payload = Base64UrlUnpadded::encode_string(&payload);

        Ok(format!("{}.{}", header, payload))
    }

    pub async fn sign<S: SigningKeystore>(&self, store: &S) -> anyhow::Result<JsonWebTokenParts> {
        let payload = self.serialize()?;
        let signature = store.sign(&self.header, payload.as_bytes()).await?;
        Ok(JsonWebTokenParts { payload, signature })
    }
}

impl<T> DecodedJsonWebToken<T> {
    pub fn new(header: JwtHeader, payload: T) -> Self {
        Self { header, payload }
    }

    pub fn claims(&self) -> &T {
        &self.payload
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

    pub fn verify<T, S: VerifyingKeystore>(
        &self,
        decoded: &DecodedJsonWebToken<T>,
        store: &S,
    ) -> S::Future
    where
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        store.verify(&decoded.header, self.payload.as_bytes(), &self.signature)
    }

    pub async fn decode_and_verify<T: DeserializeOwned, S: VerifyingKeystore>(
        &self,
        store: &S,
    ) -> anyhow::Result<DecodedJsonWebToken<T>>
    where
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        let decoded = self.decode()?;
        self.verify(&decoded, store).await?;
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
    use super::*;
    use crate::SharedSecret;

    #[tokio::test]
    async fn decode_hs256() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let jwt: JsonWebTokenParts = jwt.parse().unwrap();
        let secret = "your-256-bit-secret";
        println!("{:?}", jwt);
        let store = SharedSecret::new(&secret);
        let jwt: DecodedJsonWebToken<serde_json::Value> =
            jwt.decode_and_verify(&store).await.unwrap();

        assert_eq!(jwt.header.typ, Some("JWT".to_string()));
        assert_eq!(jwt.header.alg, JsonWebSignatureAlg::Hs256);
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
