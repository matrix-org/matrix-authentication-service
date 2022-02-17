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

use std::{collections::HashSet, future::Ready};

use anyhow::bail;
use async_trait::async_trait;
use digest::{InvalidLength, MacError};
use hmac::{Hmac, Mac};
use mas_iana::jose::JsonWebSignatureAlg;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;

use super::{SigningKeystore, VerifyingKeystore};
use crate::JwtHeader;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key")]
    InvalidKey(#[from] InvalidLength),

    #[error("unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error("signature verification failed")]
    Verification(#[from] MacError),
}

pub struct SharedSecret<'a> {
    inner: &'a [u8],
}

impl<'a> SharedSecret<'a> {
    pub fn new(source: &'a impl AsRef<[u8]>) -> Self {
        Self {
            inner: source.as_ref(),
        }
    }

    fn verify_sync(
        &self,
        header: &JwtHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match header.alg() {
            JsonWebSignatureAlg::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.inner)?;
                mac.update(payload);
                mac.verify(signature.into())?;
            }

            JsonWebSignatureAlg::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(self.inner)?;
                mac.update(payload);
                mac.verify(signature.into())?;
            }

            JsonWebSignatureAlg::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.inner)?;
                mac.update(payload);
                mac.verify(signature.into())?;
            }

            alg => return Err(Error::UnsupportedAlgorithm { alg }),
        };

        Ok(())
    }
}

#[async_trait]
impl<'a> SigningKeystore for SharedSecret<'a> {
    fn supported_algorithms(&self) -> HashSet<JsonWebSignatureAlg> {
        let mut algorithms = HashSet::with_capacity(3);

        algorithms.insert(JsonWebSignatureAlg::Hs256);
        algorithms.insert(JsonWebSignatureAlg::Hs384);
        algorithms.insert(JsonWebSignatureAlg::Hs512);

        algorithms
    }

    async fn prepare_header(&self, alg: JsonWebSignatureAlg) -> anyhow::Result<JwtHeader> {
        if !matches!(
            alg,
            JsonWebSignatureAlg::Hs256 | JsonWebSignatureAlg::Hs384 | JsonWebSignatureAlg::Hs512,
        ) {
            bail!("unsupported algorithm")
        }

        Ok(JwtHeader::new(alg))
    }

    async fn sign(&self, header: &JwtHeader, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        // TODO: do the signing in a blocking task
        // TODO: should we bail out if the key is too small?
        let signature = match header.alg() {
            JsonWebSignatureAlg::Hs256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.inner)?;
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }

            JsonWebSignatureAlg::Hs384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(self.inner)?;
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }

            JsonWebSignatureAlg::Hs512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.inner)?;
                mac.update(msg);
                mac.finalize().into_bytes().to_vec()
            }

            _ => bail!("unsupported algorithm"),
        };

        Ok(signature)
    }
}

impl<'a> VerifyingKeystore for SharedSecret<'a> {
    type Error = Error;
    type Future = Ready<Result<(), Self::Error>>;

    fn verify(&self, header: &JwtHeader, payload: &[u8], signature: &[u8]) -> Self::Future {
        std::future::ready(self.verify_sync(header, payload, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_secret() {
        let secret = "super-complicated-secret-that-should-be-big-enough-for-sha512";
        let message = "this is the message to sign".as_bytes();
        let store = SharedSecret::new(&secret);
        for alg in [
            JsonWebSignatureAlg::Hs256,
            JsonWebSignatureAlg::Hs384,
            JsonWebSignatureAlg::Hs512,
        ] {
            let header = store.prepare_header(alg).await.unwrap();
            assert_eq!(header.alg(), alg);
            let signature = store.sign(&header, message).await.unwrap();
            store.verify(&header, message, &signature).await.unwrap();
        }
    }
}
