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

use std::future::Ready;

use digest::Digest;
use mas_iana::jose::{JsonWebKeyType, JsonWebSignatureAlg};
use rsa::{PublicKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signature, Verifier};
use thiserror::Error;

use crate::{JsonWebKey, JsonWebKeySet, JsonWebSignatureHeader, VerifyingKeystore};

#[derive(Debug, Error)]
pub enum Error {
    #[error("key not found")]
    KeyNotFound,

    #[error("multiple key matched")]
    MultipleKeyMatched,

    #[error(r#"missing "kid" field in header"#)]
    MissingKid,

    #[error(transparent)]
    Rsa(#[from] rsa::errors::Error),

    #[error("unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error(transparent)]
    Signature(#[from] signature::Error),

    #[error("invalid {kty} key")]
    InvalidKey {
        kty: JsonWebKeyType,
        source: anyhow::Error,
    },
}

struct KeyConstraint<'a> {
    kty: Option<JsonWebKeyType>,
    alg: Option<JsonWebSignatureAlg>,
    kid: Option<&'a str>,
}

impl<'a> KeyConstraint<'a> {
    fn matches(&self, key: &'a JsonWebKey) -> bool {
        // If a specific KID was asked, match the key only if it has a matching kid
        // field
        if let Some(kid) = self.kid {
            if key.kid() != Some(kid) {
                return false;
            }
        }

        if let Some(kty) = self.kty {
            if key.kty() != kty {
                return false;
            }
        }

        if let Some(alg) = self.alg {
            if key.alg() != None && key.alg() != Some(alg) {
                return false;
            }
        }

        true
    }

    fn find_keys(&self, key_set: &'a JsonWebKeySet) -> Vec<&'a JsonWebKey> {
        key_set.iter().filter(|k| self.matches(k)).collect()
    }
}

pub struct StaticJwksStore {
    key_set: JsonWebKeySet,
}

impl StaticJwksStore {
    #[must_use]
    pub fn new(key_set: JsonWebKeySet) -> Self {
        Self { key_set }
    }

    fn find_key<'a>(&'a self, constraint: &KeyConstraint<'a>) -> Result<&'a JsonWebKey, Error> {
        let keys = constraint.find_keys(&self.key_set);

        match &keys[..] {
            [one] => Ok(one),
            [] => Err(Error::KeyNotFound),
            _ => Err(Error::MultipleKeyMatched),
        }
    }

    fn find_rsa_key(&self, kid: Option<&str>) -> Result<RsaPublicKey, Error> {
        let constraint = KeyConstraint {
            kty: Some(JsonWebKeyType::Rsa),
            kid,
            alg: None,
        };

        let key = self.find_key(&constraint)?;

        let key = key
            .params()
            .clone()
            .try_into()
            .map_err(|source| Error::InvalidKey {
                kty: JsonWebKeyType::Rsa,
                source,
            })?;

        Ok(key)
    }

    fn find_ecdsa_key(
        &self,
        kid: Option<&str>,
    ) -> Result<ecdsa::VerifyingKey<p256::NistP256>, Error> {
        let constraint = KeyConstraint {
            kty: Some(JsonWebKeyType::Ec),
            kid,
            alg: None,
        };

        let key = self.find_key(&constraint)?;

        let key = key
            .params()
            .clone()
            .try_into()
            .map_err(|source| Error::InvalidKey {
                kty: JsonWebKeyType::Ec,
                source,
            })?;

        Ok(key)
    }

    #[tracing::instrument(skip(self))]
    fn verify_sync(
        &self,
        header: &JsonWebSignatureHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let kid = header.kid();
        match header.alg() {
            JsonWebSignatureAlg::Rs256 => {
                let key = self.find_rsa_key(kid)?;

                let digest = {
                    let mut digest = Sha256::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                key.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Rs384 => {
                let key = self.find_rsa_key(kid)?;

                let digest = {
                    let mut digest = Sha384::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                key.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Rs512 => {
                let key = self.find_rsa_key(kid)?;

                let digest = {
                    let mut digest = Sha512::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                key.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Es256 => {
                let key = self.find_ecdsa_key(kid)?;

                let signature = ecdsa::Signature::from_bytes(signature)?;

                key.verify(payload, &signature)?;
            }

            alg => return Err(Error::UnsupportedAlgorithm { alg }),
        };

        Ok(())
    }
}

impl VerifyingKeystore for StaticJwksStore {
    type Error = Error;
    type Future = Ready<Result<(), Self::Error>>;

    fn verify(
        &self,
        header: &JsonWebSignatureHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> Self::Future {
        std::future::ready(self.verify_sync(header, payload, signature))
    }
}
