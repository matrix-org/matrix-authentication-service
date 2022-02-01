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

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaCha20Poly1305,
};
use mas_jose::StaticKeystore;
use pkcs8::DecodePrivateKey;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::{fs::File, io::AsyncReadExt, task};
use tracing::info;

use super::ConfigurationSection;

/// Helps encrypting and decrypting data
#[derive(Clone)]
pub struct Encrypter {
    aead: Arc<ChaCha20Poly1305>,
}

impl Encrypter {
    /// Creates an [`Encrypter`] out of an encryption key
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let aead = Arc::new(aead);
        Self { aead }
    }

    /// Encrypt a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to encrypt
    pub fn encrypt(&self, nonce: &[u8; 12], decrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.encrypt(nonce, decrypted)?;
        Ok(encrypted)
    }

    /// Decrypts a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to decrypt
    pub fn decrypt(&self, nonce: &[u8; 12], encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.decrypt(nonce, encrypted)?;
        Ok(encrypted)
    }
}

fn example_secret() -> &'static str {
    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrPath {
    Key(String),
    Path(PathBuf),
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    r#type: KeyType,
    #[serde(flatten)]
    key: KeyOrPath,
}

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretsConfig {
    /// Encryption key for secure cookies
    #[schemars(
        with = "String",
        regex(pattern = r"[0-9a-fA-F]{64}"),
        example = "example_secret"
    )]
    #[serde_as(as = "serde_with::hex::Hex")]
    encryption: [u8; 32],

    /// List of private keys to use for signing and encrypting payloads
    #[serde(default)]
    keys: Vec<KeyConfig>,
}

impl SecretsConfig {
    /// Derive a signing and verifying keystore out of the config
    ///
    /// # Errors
    ///
    /// Returns an error when a key could not be imported
    pub async fn key_store(&self) -> anyhow::Result<StaticKeystore> {
        let mut store = StaticKeystore::new();

        for item in &self.keys {
            // Read the key either embedded in the config file or on disk
            let mut buf = Vec::new();
            let (key_as_bytes, key_as_str) = match &item.key {
                KeyOrPath::Key(key) => (key.as_bytes(), Some(key.as_str())),
                KeyOrPath::Path(path) => {
                    let mut file = File::open(path).await?;
                    file.read_to_end(&mut buf).await?;

                    (&buf[..], std::str::from_utf8(&buf).ok())
                }
            };

            match item.r#type {
                // TODO: errors are not well carried here
                KeyType::Ecdsa => {
                    // First try to read it as DER from the bytes
                    let mut key = p256::SecretKey::from_pkcs1_der(key_as_bytes)
                        .or_else(|_| p256::SecretKey::from_pkcs8_der(key_as_bytes))
                        .or_else(|_| p256::SecretKey::from_sec1_der(key_as_bytes));

                    // If the file was a valid string, try reading it as PEM
                    if let Some(key_as_str) = key_as_str {
                        key = key
                            .or_else(|_| p256::SecretKey::from_pkcs1_pem(key_as_str))
                            .or_else(|_| p256::SecretKey::from_pkcs8_pem(key_as_str))
                            .or_else(|_| p256::SecretKey::from_sec1_pem(key_as_str));
                    }

                    let key = key?;
                    store.add_ecdsa_key(key.into())?;
                }
                KeyType::Rsa => {
                    let mut key = rsa::RsaPrivateKey::from_pkcs1_der(key_as_bytes)
                        .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_der(key_as_bytes));

                    if let Some(key_as_str) = key_as_str {
                        key = key
                            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(key_as_str))
                            .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(key_as_str));
                    }

                    let key = key?;
                    store.add_rsa_key(key)?;
                }
            }
        }

        Ok(store)
    }

    /// Derive an [`Encrypter`] out of the config
    #[must_use]
    pub fn encrypter(&self) -> Encrypter {
        Encrypter::new(&self.encryption)
    }
}

#[async_trait]
impl ConfigurationSection<'_> for SecretsConfig {
    fn path() -> &'static str {
        "secrets"
    }

    #[tracing::instrument]
    async fn generate() -> anyhow::Result<Self> {
        info!("Generating keys...");

        let span = tracing::info_span!("rsa");
        let rsa_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let mut rng = rand::thread_rng();
            let ret =
                RsaPrivateKey::new(&mut rng, 2048).context("could not generate RSA private key");
            info!("Done generating RSA key");
            ret
        })
        .await
        .context("could not join blocking task")??;
        let rsa_key = KeyConfig {
            r#type: KeyType::Rsa,
            key: KeyOrPath::Key(
                rsa_key
                    .to_pkcs1_pem(pem_rfc7468::LineEnding::LF)?
                    .to_string(),
            ),
        };

        let span = tracing::info_span!("ecdsa");
        let ecdsa_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let rng = rand::thread_rng();
            let ret = p256::SecretKey::random(rng);
            info!("Done generating ECDSA key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ecdsa_key = KeyConfig {
            r#type: KeyType::Ecdsa,
            key: KeyOrPath::Key(ecdsa_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        Ok(Self {
            encryption: rand::random(),
            keys: vec![rsa_key, ecdsa_key],
        })
    }

    fn test() -> Self {
        let rsa_key = KeyConfig {
            r#type: KeyType::Rsa,
            key: KeyOrPath::Key(
                indoc::indoc! {r#"
                  -----BEGIN PRIVATE KEY-----
                  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAymS2RkeIZo7pUeEN
                  QUGCG4GLJru5jzxomO9jiNr5D/oRcerhpQVc9aCpBfAAg4l4a1SmYdBzWqX0X5pU
                  scgTtQIDAQABAkEArNIMlrxUK4bSklkCcXtXdtdKE9vuWfGyOw0GyAB69fkEUBxh
                  3j65u+u3ZmW+bpMWHgp1FtdobE9nGwb2VBTWAQIhAOyU1jiUEkrwKK004+6b5QRE
                  vC9UI2vDWy5vioMNx5Y1AiEA2wGAJ6ETF8FF2Vd+kZlkKK7J0em9cl0gbJDsWIEw
                  N4ECIEyWYkMurD1WQdTQqnk0Po+DMOihdFYOiBYgRdbnPxWBAiEAmtd0xJAd7622
                  tPQniMnrBtiN2NxqFXHCev/8Gpc8gAECIBcaPcF59qVeRmYrfqzKBxFm7LmTwlAl
                  Gh7BNzCeN+D6
                  -----END PRIVATE KEY-----
                "#}
                .to_string(),
            ),
        };
        let ecdsa_key = KeyConfig {
            r#type: KeyType::Ecdsa,
            key: KeyOrPath::Key(
                indoc::indoc! {r#"
                  -----BEGIN PRIVATE KEY-----
                  MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                  NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                  OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                  -----END PRIVATE KEY-----
                "#}
                .to_string(),
            ),
        };

        Self {
            encryption: [0xEA; 32],
            keys: vec![rsa_key, ecdsa_key],
        }
    }
}
