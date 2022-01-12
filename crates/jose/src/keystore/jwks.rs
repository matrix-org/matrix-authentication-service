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

use std::collections::HashMap;

use anyhow::bail;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use digest::Digest;
use mas_iana::jose::{JsonWebKeyType, JsonWebSignatureAlg};
use rsa::{PublicKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signature, Verifier};
use tokio::sync::RwLock;

use crate::{ExportJwks, JsonWebKeySet, JwtHeader, VerifyingKeystore};

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

    fn find_rsa_key(&self, kid: String) -> anyhow::Result<RsaPublicKey> {
        let index = *self
            .index
            .get(&(JsonWebKeyType::Rsa, kid))
            .ok_or_else(|| anyhow::anyhow!("key not found"))?;

        let key = self
            .key_set
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("invalid index"))?;

        let key = key.params().clone().try_into()?;

        Ok(key)
    }

    fn find_ecdsa_key(&self, kid: String) -> anyhow::Result<ecdsa::VerifyingKey<p256::NistP256>> {
        let index = *self
            .index
            .get(&(JsonWebKeyType::Ec, kid))
            .ok_or_else(|| anyhow::anyhow!("key not found"))?;

        let key = self
            .key_set
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("invalid index"))?;

        let key = key.params().clone().try_into()?;

        Ok(key)
    }
}

#[async_trait]
impl VerifyingKeystore for &StaticJwksStore {
    async fn verify(
        self,
        header: &JwtHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        let kid = header
            .kid()
            .ok_or_else(|| anyhow::anyhow!("missing kid"))?
            .to_string();
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

            _ => bail!("unsupported algorithm"),
        };

        Ok(())
    }
}

enum RemoteKeySet {
    Pending,
    Errored {
        at: DateTime<Utc>,
        error: anyhow::Error,
    },
    Fulfilled {
        at: DateTime<Utc>,
        store: StaticJwksStore,
    },
}

impl Default for RemoteKeySet {
    fn default() -> Self {
        Self::Pending
    }
}

impl RemoteKeySet {
    fn fullfill(&mut self, key_set: JsonWebKeySet) {
        *self = Self::Fulfilled {
            at: Utc::now(),
            store: StaticJwksStore::new(key_set),
        }
    }

    fn error(&mut self, error: anyhow::Error) {
        *self = Self::Errored {
            at: Utc::now(),
            error,
        }
    }

    fn should_refresh(&self) -> bool {
        let now = Utc::now();
        match self {
            Self::Pending => true,
            Self::Errored { at, .. } if *at - now > Duration::minutes(5) => true,
            Self::Fulfilled { at, .. } if *at - now > Duration::hours(1) => true,
            _ => false,
        }
    }

    fn should_force_refresh(&self) -> bool {
        let now = Utc::now();
        match self {
            Self::Pending => true,
            Self::Errored { at, .. } | Self::Fulfilled { at, .. }
                if *at - now > Duration::minutes(5) =>
            {
                true
            }
            _ => false,
        }
    }
}

pub struct JwksStore<T>
where
    T: ExportJwks,
{
    exporter: T,
    cache: RwLock<RemoteKeySet>,
}

impl<T: ExportJwks> JwksStore<T> {
    pub fn new(exporter: T) -> Self {
        Self {
            exporter,
            cache: RwLock::default(),
        }
    }

    async fn should_refresh(&self) -> bool {
        let cache = self.cache.read().await;
        cache.should_refresh()
    }

    async fn refresh(&self) {
        let mut cache = self.cache.write().await;

        if cache.should_force_refresh() {
            let jwks = self.exporter.export_jwks().await;

            match jwks {
                Ok(jwks) => cache.fullfill(jwks),
                Err(err) => cache.error(err),
            }
        }
    }
}

#[async_trait]
impl<T: ExportJwks + Send + Sync> VerifyingKeystore for &JwksStore<T> {
    async fn verify(
        self,
        header: &JwtHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        if self.should_refresh().await {
            self.refresh().await;
        }

        let cache = self.cache.read().await;
        // TODO: we could bubble up the underlying error here
        let store = match &*cache {
            RemoteKeySet::Pending => bail!("inconsistent cache state"),
            RemoteKeySet::Errored { error, .. } => bail!("cache in error state {}", error),
            RemoteKeySet::Fulfilled { store, .. } => store,
        };

        store.verify(header, payload, signature).await?;

        Ok(())
    }
}
