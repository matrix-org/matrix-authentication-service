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

use std::{collections::HashMap, future::Ready};

use digest::Digest;
use mas_iana::jose::{JsonWebKeyType, JsonWebSignatureAlg};
use rsa::{PublicKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signature, Verifier};
use thiserror::Error;

use crate::{JsonWebKeySet, JwtHeader, VerifyingKeystore};

#[derive(Debug, Error)]
pub enum Error {
    #[error("key not found")]
    KeyNotFound,

    #[error("invalid index")]
    InvalidIndex,

    #[error(r#"missing "kid" field in header"#)]
    MissingKid,

    #[error(transparent)]
    Rsa(#[from] rsa::errors::Error),

    #[error("unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error(transparent)]
    Signature(#[from] signature::Error),

    #[error("invalid {kty} key {kid}")]
    InvalidKey {
        kty: JsonWebKeyType,
        kid: String,
        source: anyhow::Error,
    },
}

pub struct StaticJwksStore {
    key_set: JsonWebKeySet,
    index: HashMap<(JsonWebKeyType, String), usize>,
}

impl StaticJwksStore {
    #[must_use]
    pub fn new(key_set: JsonWebKeySet) -> Self {
        let index = key_set
            .iter()
            .enumerate()
            .filter_map(|(index, key)| {
                let kid = key.kid()?.to_string();
                let kty = key.kty();

                Some(((kty, kid), index))
            })
            .collect();

        Self { key_set, index }
    }

    fn find_rsa_key(&self, kid: String) -> Result<RsaPublicKey, Error> {
        let index = *self
            .index
            .get(&(JsonWebKeyType::Rsa, kid.clone()))
            .ok_or(Error::KeyNotFound)?;

        let key = self.key_set.get(index).ok_or(Error::InvalidIndex)?;

        let key = key
            .params()
            .clone()
            .try_into()
            .map_err(|source| Error::InvalidKey {
                kty: JsonWebKeyType::Rsa,
                kid,
                source,
            })?;

        Ok(key)
    }

    fn find_ecdsa_key(&self, kid: String) -> Result<ecdsa::VerifyingKey<p256::NistP256>, Error> {
        let index = *self
            .index
            .get(&(JsonWebKeyType::Ec, kid.clone()))
            .ok_or(Error::KeyNotFound)?;

        let key = self.key_set.get(index).ok_or(Error::InvalidIndex)?;

        let key = key
            .params()
            .clone()
            .try_into()
            .map_err(|source| Error::InvalidKey {
                kty: JsonWebKeyType::Ec,
                kid,
                source,
            })?;

        Ok(key)
    }

    fn verify_sync(
        &self,
        header: &JwtHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let kid = header.kid().ok_or(Error::MissingKid)?.to_string();
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

    fn verify(&self, header: &JwtHeader, payload: &[u8], signature: &[u8]) -> Self::Future {
        std::future::ready(self.verify_sync(header, payload, signature))
    }
}
