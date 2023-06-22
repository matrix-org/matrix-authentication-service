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

use std::sync::Arc;

use aead::Aead;
use base64ct::{Base64, Encoding};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use cookie::Key;
use generic_array::GenericArray;
use thiserror::Error;

/// Helps encrypting and decrypting data
#[derive(Clone)]
pub struct Encrypter {
    cookie_key: Arc<Key>,
    aead: Arc<ChaCha20Poly1305>,
}

impl From<Encrypter> for Key {
    fn from(e: Encrypter) -> Self {
        e.cookie_key.as_ref().clone()
    }
}

#[derive(Debug, Error)]
#[error("Decryption error")]
pub enum DecryptError {
    Aead(#[from] aead::Error),
    Base64(#[from] base64ct::Error),
    Shape,
}

impl Encrypter {
    /// Creates an [`Encrypter`] out of an encryption key
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let cookie_key = Key::derive_from(&key[..]);
        let cookie_key = Arc::new(cookie_key);
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let aead = Arc::new(aead);
        Self { cookie_key, aead }
    }

    /// Encrypt a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to encrypt
    pub fn encrypt(&self, nonce: &[u8; 12], decrypted: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.encrypt(nonce, decrypted)?;
        Ok(encrypted)
    }

    /// Decrypts a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to decrypt
    pub fn decrypt(&self, nonce: &[u8; 12], encrypted: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.decrypt(nonce, encrypted)?;
        Ok(encrypted)
    }

    /// Encrypt a payload to a self-contained base64-encoded string
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to encrypt
    pub fn encrypt_to_string(&self, decrypted: &[u8]) -> Result<String, aead::Error> {
        let nonce = rand::random();
        let encrypted = self.encrypt(&nonce, decrypted)?;
        let encrypted = [&nonce[..], &encrypted].concat();
        let encrypted = Base64::encode_string(&encrypted);
        Ok(encrypted)
    }

    /// Decrypt a payload from a self-contained base64-encoded string
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to decrypt
    pub fn decrypt_string(&self, encrypted: &str) -> Result<Vec<u8>, DecryptError> {
        let encrypted = Base64::decode_vec(encrypted)?;

        let nonce: &[u8; 12] = encrypted
            .get(0..12)
            .ok_or(DecryptError::Shape)?
            .try_into()
            .map_err(|_| DecryptError::Shape)?;

        let payload = encrypted.get(12..).ok_or(DecryptError::Shape)?;

        let decrypted_client_secret = self.decrypt(nonce, payload)?;

        Ok(decrypted_client_secret)
    }
}
