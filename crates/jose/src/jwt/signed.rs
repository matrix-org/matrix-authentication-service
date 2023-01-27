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

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::thread_rng;
use serde::{de::DeserializeOwned, Serialize};
use signature::{rand_core::CryptoRngCore, RandomizedSigner, SignatureEncoding, Verifier};
use thiserror::Error;

use super::{header::JsonWebSignatureHeader, raw::RawJwt};
use crate::{constraints::ConstraintSet, jwk::PublicJsonWebKeySet};

#[derive(Clone, PartialEq, Eq)]
pub struct Jwt<'a, T> {
    raw: RawJwt<'a>,
    header: JsonWebSignatureHeader,
    payload: T,
    signature: Vec<u8>,
}

impl<'a, T> std::fmt::Display for Jwt<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl<'a, T> std::fmt::Debug for Jwt<'a, T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwt")
            .field("raw", &"...")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &"...")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum JwtDecodeError {
    #[error(transparent)]
    RawDecode {
        #[from]
        inner: super::raw::DecodeError,
    },

    #[error("failed to decode JWT header")]
    DecodeHeader {
        #[source]
        inner: base64ct::Error,
    },

    #[error("failed to deserialize JWT header")]
    DeserializeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to decode JWT payload")]
    DecodePayload {
        #[source]
        inner: base64ct::Error,
    },

    #[error("failed to deserialize JWT payload")]
    DeserializePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to decode JWT signature")]
    DecodeSignature {
        #[source]
        inner: base64ct::Error,
    },
}

impl JwtDecodeError {
    fn decode_header(inner: base64ct::Error) -> Self {
        Self::DecodeHeader { inner }
    }

    fn deserialize_header(inner: serde_json::Error) -> Self {
        Self::DeserializeHeader { inner }
    }

    fn decode_payload(inner: base64ct::Error) -> Self {
        Self::DecodePayload { inner }
    }

    fn deserialize_payload(inner: serde_json::Error) -> Self {
        Self::DeserializePayload { inner }
    }

    fn decode_signature(inner: base64ct::Error) -> Self {
        Self::DecodeSignature { inner }
    }
}

impl<'a, T> TryFrom<RawJwt<'a>> for Jwt<'a, T>
where
    T: DeserializeOwned,
{
    type Error = JwtDecodeError;
    fn try_from(raw: RawJwt<'a>) -> Result<Self, Self::Error> {
        let header_reader =
            base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.header().as_bytes())
                .map_err(JwtDecodeError::decode_header)?;
        let header =
            serde_json::from_reader(header_reader).map_err(JwtDecodeError::deserialize_header)?;

        let payload_reader =
            base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.payload().as_bytes())
                .map_err(JwtDecodeError::decode_payload)?;
        let payload =
            serde_json::from_reader(payload_reader).map_err(JwtDecodeError::deserialize_payload)?;

        let signature = Base64UrlUnpadded::decode_vec(raw.signature())
            .map_err(JwtDecodeError::decode_signature)?;

        Ok(Self {
            raw,
            header,
            payload,
            signature,
        })
    }
}

impl<'a, T> TryFrom<&'a str> for Jwt<'a, T>
where
    T: DeserializeOwned,
{
    type Error = JwtDecodeError;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let raw = RawJwt::try_from(value)?;
        Self::try_from(raw)
    }
}

impl<T> TryFrom<String> for Jwt<'static, T>
where
    T: DeserializeOwned,
{
    type Error = JwtDecodeError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let raw = RawJwt::try_from(value)?;
        Self::try_from(raw)
    }
}

#[derive(Debug, Error)]
pub enum JwtVerificationError {
    #[error("failed to parse signature")]
    ParseSignature,

    #[error("signature verification failed")]
    Verify {
        #[source]
        inner: signature::Error,
    },
}

impl JwtVerificationError {
    #[allow(clippy::needless_pass_by_value)]
    fn parse_signature<E>(_inner: E) -> Self {
        Self::ParseSignature
    }

    fn verify(inner: signature::Error) -> Self {
        Self::Verify { inner }
    }
}

#[derive(Debug, Error, Default)]
#[error("none of the keys worked")]
pub struct NoKeyWorked {
    _inner: (),
}

impl<'a, T> Jwt<'a, T> {
    pub fn header(&self) -> &JsonWebSignatureHeader {
        &self.header
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_owned(self) -> Jwt<'static, T> {
        Jwt {
            raw: self.raw.into_owned(),
            header: self.header,
            payload: self.payload,
            signature: self.signature,
        }
    }

    pub fn verify<K, S>(&self, key: &K) -> Result<(), JwtVerificationError>
    where
        K: Verifier<S>,
        S: SignatureEncoding,
    {
        let signature =
            S::try_from(&self.signature).map_err(JwtVerificationError::parse_signature)?;

        key.verify(self.raw.signed_part().as_bytes(), &signature)
            .map_err(JwtVerificationError::verify)
    }

    pub fn verify_with_shared_secret(&self, secret: Vec<u8>) -> Result<(), NoKeyWorked> {
        let verifier = crate::jwa::SymmetricKey::new_for_alg(secret, self.header().alg())
            .map_err(|_| NoKeyWorked::default())?;

        self.verify(&verifier).map_err(|_| NoKeyWorked::default())?;

        Ok(())
    }

    pub fn verify_with_jwks(&self, jwks: &PublicJsonWebKeySet) -> Result<(), NoKeyWorked> {
        let constraints = ConstraintSet::from(self.header());
        let candidates = constraints.filter(&**jwks);

        for candidate in candidates {
            let key = match crate::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
                candidate.params(),
                self.header().alg(),
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };

            match self.verify(&key) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }

        Err(NoKeyWorked::default())
    }

    pub fn as_str(&'a self) -> &'a str {
        &self.raw
    }

    pub fn into_string(self) -> String {
        self.raw.into()
    }

    pub fn into_parts(self) -> (JsonWebSignatureHeader, T) {
        (self.header, self.payload)
    }
}

#[derive(Debug, Error)]
pub enum JwtSignatureError {
    #[error("failed to serialize header")]
    EncodeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to serialize payload")]
    EncodePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to sign")]
    Signature {
        #[from]
        inner: signature::Error,
    },
}

impl JwtSignatureError {
    fn encode_header(inner: serde_json::Error) -> Self {
        Self::EncodeHeader { inner }
    }

    fn encode_payload(inner: serde_json::Error) -> Self {
        Self::EncodePayload { inner }
    }
}

impl<T> Jwt<'static, T> {
    pub fn sign<K, S>(
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        #[allow(clippy::disallowed_methods)]
        Self::sign_with_rng(&mut thread_rng(), header, payload, key)
    }

    pub fn sign_with_rng<R, K, S>(
        rng: &mut R,
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        R: CryptoRngCore,
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        let header_ = serde_json::to_vec(&header).map_err(JwtSignatureError::encode_header)?;
        let header_ = Base64UrlUnpadded::encode_string(&header_);

        let payload_ = serde_json::to_vec(&payload).map_err(JwtSignatureError::encode_payload)?;
        let payload_ = Base64UrlUnpadded::encode_string(&payload_);

        let mut inner = format!("{header_}.{payload_}");

        let first_dot = header_.len();
        let second_dot = inner.len();

        let signature = key.try_sign_with_rng(rng, inner.as_bytes())?.to_vec();
        let signature_ = Base64UrlUnpadded::encode_string(&signature);
        inner.reserve_exact(1 + signature_.len());
        inner.push('.');
        inner.push_str(&signature_);

        let raw = RawJwt::new(inner, first_dot, second_dot);

        Ok(Self {
            raw,
            header,
            payload,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use mas_iana::jose::JsonWebSignatureAlg;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_jwt_decode() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let jwt: Jwt<'_, serde_json::Value> = Jwt::try_from(jwt).unwrap();
        assert_eq!(jwt.raw.header(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(
            jwt.raw.payload(),
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
        assert_eq!(
            jwt.raw.signature(),
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        assert_eq!(jwt.raw.signed_part(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Es256);
        let payload = serde_json::json!({"hello": "world"});

        let key = ecdsa::SigningKey::<p256::NistP256>::random(&mut thread_rng());
        let signed = Jwt::sign::<_, ecdsa::Signature<_>>(header, payload, &key).unwrap();
        signed
            .verify::<_, ecdsa::Signature<_>>(key.verifying_key())
            .unwrap();
    }
}
