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

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Ready,
    task::Poll,
};

use anyhow::bail;
use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use digest::Digest;
use ecdsa::{SigningKey, VerifyingKey};
use mas_iana::jose::{JsonWebKeyUse, JsonWebSignatureAlg};
use p256::{NistP256, PublicKey};
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::{PublicKey as _, RsaPrivateKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signature, Signer, Verifier};
use tower::Service;

use super::{SigningKeystore, VerifyingKeystore};
use crate::{JsonWebKey, JsonWebKeySet, JwtHeader};

// Generate with
//  openssl genrsa 2048
const TEST_RSA_PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1j7Y2CH6Ss8tgaNvcQPaRJKnCZD8ABqNPyKDWLQLph6Zi7gZ
GqmRtTzMuevo2ezpkbCiQAPEp1ms022P92bB+uqG7xmzHTzbwLtnq3OAdjmrnaFV
I4v89WHUsTXX9hiYOK5dOM81bNZ6muxWZ0L/xw4jVWe7xkqnp2Lluq0HknlzP5yJ
UEikf5BkpX0iyIu2/X4r8YVp8uzG34l/8qBx6k3rO2VkOQOSybZj1oij5KZCusnu
QjJLKWXCqJToWE6iVn+Q0N6ySDLgmJ7Zq0Sou/9N/oWKn94FOsouQgET5NuzoIFR
qTb321fQ8gbqt/OupBbBKEo1qUU+cS77TD/AuQIDAQABAoIBAQDLSZzmD+93lnf+
f36ZxOcRk/nNGPYUfx0xH+VzgHthJ73YFlozs1xflQ5JB/DM/4BsziZWCX1KsctM
XrRxMt6y4GAidcc/4eQ+T1RCGfl1tKkDi/bGIOloSGjRsV5208V0WvZ3lh2CZUy2
vbQKjUc3sFGUkzZYI7RLHosPA2mg78IVuSnqvNaU0TgA2KkaxWs6Ecr/ys80cUvj
KKj04DmX5xaXwUKmz353i5gIt3aY3G5CAw5fU/ocDKR8nzVCpBAGbRRiUaVKIT06
APSkLDTUnxSYtHtDJGHjgU/TsvAwTA92J3ue5Ysu9xTE+WyHA6Rgux7RQSD/wWHr
LdRPwxPFAoGBAOytMPh/f2zKmotanjho0QNfhAUHoQUfPudYT0nnDceOsi1jYWbQ
c/wPeQQC4Hp/pTUrkSIQPEz/hSxzZ6RPxxuGB8O94I0uLwQK4V1UwbgfsRa9zQzW
n0kgKZ8w8h8B7qyiKyIAnZzvKtNEnKrzrct4HsN3OEoXTwuAUYlvWtQTAoGBAOe8
0liNaH9V6ecZiojkRR1tiQkr/dCV+a13eXXaRA/8y/3wKCQ4idYncclQJTLKsAwW
hHuDd4uLgtifREVIBD2jGdlznNr9HQNuZgwjuUoH+r1YLGgiMWeVYSr0m8lyDlQl
BJKTAphrqo6VJWDAnM18v+by//yRleSjVMqZ3zmDAoGBAMpA0rl5EyagGON/g/hG
sl8Ej+hQdazP38yJbfCEsATaD6+z3rei6Yr8mfjwkG5+iGrgmT0XzMAsF909ndMP
jeIabqY6rBtZ3TnCJobAeG9lPctmVUVkX2h5QLhWdoJC/3iteNis2AQVam5yksOQ
S/O16ew2BHdkZds5Q/SDoYXbAoGAK9tVZ8LjWu30hXMU/9FLr0USoTS9JWOszAKH
byFuriPmq1lvD2PP2kK+yx2q3JD1fmQokIOR9Uvi6IJD1mTJwKyEcN3reppailKz
Z2q/X15hOsJcLR0DgpoHuKxwa1B1m8Ehu2etHxGJRtC9MTFiu5T3cIrenXskBhBP
NMSoNWcCgYAD3u3zdeVo3gVoxneS7GNVI2WBhjtqgNIbINuxGZvfztm7+vNPE6sQ
VL8i+09uoM1H6sXbe2XXORmtW0j/6MmYhSoBXNdqWTNAiyNRhwEQtowqgl5R7PBu
//QZTF1z62R9IKDMRG3f5Wn8e1Dys6tXBuG603g+Dkkc/km476mrgw==
-----END RSA PRIVATE KEY-----";

// Generate with
//  openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt
const TEST_ECDSA_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+tHxet7G+uar2Cef
iYPb7jv3uzncFtwJ7RhDOvEA0fChRANCAATCKn2AEqa9785k+TmwkeCvLub8XGrF
ezE6bA/blaPVE3nu4SUVYKULRJQxNjeOSra8TQrlIS8e5ItbMn8Tv9KV
-----END PRIVATE KEY-----";

#[derive(Default)]
pub struct StaticKeystore {
    rsa_keys: HashMap<String, rsa::RsaPrivateKey>,
    es256_keys: HashMap<String, SigningKey<NistP256>>,
}

impl StaticKeystore {
    #[must_use]
    pub fn new() -> Self {
        StaticKeystore::default()
    }

    pub fn add_test_rsa_key(&mut self) -> anyhow::Result<()> {
        let rsa = RsaPrivateKey::from_pkcs1_pem(TEST_RSA_PKCS1_PEM)?;
        self.add_rsa_key(rsa)?;
        Ok(())
    }

    pub fn add_test_ecdsa_key(&mut self) -> anyhow::Result<()> {
        let ecdsa = SigningKey::from_pkcs8_pem(TEST_ECDSA_PKCS8_PEM)?;
        self.add_ecdsa_key(ecdsa)?;
        Ok(())
    }

    pub fn add_rsa_key(&mut self, key: rsa::RsaPrivateKey) -> anyhow::Result<()> {
        let pubkey: &RsaPublicKey = &key;
        let der = pubkey.to_pkcs1_der()?;
        let digest = {
            let mut digest = Sha256::new();
            digest.update(&der);
            digest.finalize()
        };
        // Truncate the digest to the 120 first bits
        let digest = &digest[0..15];
        let digest = Base64UrlUnpadded::encode_string(digest);
        let kid = format!("rsa-{}", digest);
        self.rsa_keys.insert(kid, key);
        Ok(())
    }

    pub fn add_ecdsa_key(&mut self, key: SigningKey<NistP256>) -> anyhow::Result<()> {
        let pubkey: PublicKey = key.verifying_key().into();
        let der = EncodePublicKey::to_public_key_der(&pubkey)?;
        let digest = {
            let mut digest = Sha256::new();
            digest.update(&der);
            digest.finalize()
        };
        // Truncate the digest to the 120 first bits
        let digest = &digest[0..15];
        let digest = Base64UrlUnpadded::encode_string(digest);
        let kid = format!("ec-{}", digest);
        self.es256_keys.insert(kid, key);
        Ok(())
    }

    fn verify_sync(
        &self,
        header: &JwtHeader,
        payload: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        let kid = header
            .kid()
            .ok_or_else(|| anyhow::anyhow!("missing kid claim in JWT header"))?;

        // TODO: do the verification in a blocking task
        match header.alg() {
            JsonWebSignatureAlg::Rs256 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("could not find RSA key in key store"))?;

                let pubkey = rsa::RsaPublicKey::from(key);

                let digest = {
                    let mut digest = Sha256::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                pubkey.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Rs384 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("could not find RSA key in key store"))?;

                let pubkey = rsa::RsaPublicKey::from(key);

                let digest = {
                    let mut digest = Sha384::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                pubkey.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Rs512 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("could not find RSA key in key store"))?;

                let pubkey = rsa::RsaPublicKey::from(key);

                let digest = {
                    let mut digest = Sha512::new();
                    digest.update(&payload);
                    digest.finalize()
                };

                pubkey.verify(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512)),
                    &digest,
                    signature,
                )?;
            }

            JsonWebSignatureAlg::Es256 => {
                let key = self
                    .es256_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("could not find ECDSA key in key store"))?;

                let pubkey = VerifyingKey::from(key);
                let signature = ecdsa::Signature::from_bytes(signature)?;

                pubkey.verify(payload, &signature)?;
            }
            _ => bail!("unsupported algorithm"),
        }

        Ok(())
    }
}

#[async_trait]
impl SigningKeystore for StaticKeystore {
    fn supported_algorithms(&self) -> HashSet<JsonWebSignatureAlg> {
        let has_rsa = !self.rsa_keys.is_empty();
        let has_es256 = !self.es256_keys.is_empty();

        let capacity = (if has_rsa { 3 } else { 0 }) + (if has_es256 { 1 } else { 0 });
        let mut algorithms = HashSet::with_capacity(capacity);

        if has_rsa {
            algorithms.insert(JsonWebSignatureAlg::Rs256);
            algorithms.insert(JsonWebSignatureAlg::Rs384);
            algorithms.insert(JsonWebSignatureAlg::Rs512);
        }

        if has_es256 {
            algorithms.insert(JsonWebSignatureAlg::Es256);
        }

        algorithms
    }

    async fn prepare_header(&self, alg: JsonWebSignatureAlg) -> anyhow::Result<JwtHeader> {
        let header = JwtHeader::new(alg);

        let kid = match alg {
            JsonWebSignatureAlg::Rs256
            | JsonWebSignatureAlg::Rs384
            | JsonWebSignatureAlg::Rs512 => self
                .rsa_keys
                .keys()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no RSA keys in keystore"))?,
            JsonWebSignatureAlg::Es256 => self
                .es256_keys
                .keys()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no ECDSA keys in keystore"))?,
            _ => bail!("unsupported algorithm"),
        };

        Ok(header.with_kid(kid))
    }

    async fn sign(&self, header: &JwtHeader, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let kid = header
            .kid()
            .ok_or_else(|| anyhow::anyhow!("missing kid from the JWT header"))?;

        // TODO: do the signing in a blocking task
        let signature = match header.alg() {
            JsonWebSignatureAlg::Rs256 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("RSA key not found in key store"))?;

                let digest = {
                    let mut digest = Sha256::new();
                    digest.update(&msg);
                    digest.finalize()
                };

                key.sign(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
                    &digest,
                )?
            }

            JsonWebSignatureAlg::Rs384 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("RSA key not found in key store"))?;

                let digest = {
                    let mut digest = Sha384::new();
                    digest.update(&msg);
                    digest.finalize()
                };

                key.sign(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384)),
                    &digest,
                )?
            }

            JsonWebSignatureAlg::Rs512 => {
                let key = self
                    .rsa_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("RSA key not found in key store"))?;

                let digest = {
                    let mut digest = Sha512::new();
                    digest.update(&msg);
                    digest.finalize()
                };

                key.sign(
                    rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512)),
                    &digest,
                )?
            }

            JsonWebSignatureAlg::Es256 => {
                let key = self
                    .es256_keys
                    .get(kid)
                    .ok_or_else(|| anyhow::anyhow!("ECDSA key not found in key store"))?;

                let signature = key.try_sign(msg)?;
                let signature: &[u8] = signature.as_ref();
                signature.to_vec()
            }

            _ => bail!("Unsupported algorithm"),
        };

        Ok(signature)
    }
}

impl VerifyingKeystore for StaticKeystore {
    type Error = anyhow::Error;
    type Future = Ready<Result<(), Self::Error>>;

    fn verify(&self, header: &JwtHeader, msg: &[u8], signature: &[u8]) -> Self::Future {
        std::future::ready(self.verify_sync(header, msg, signature))
    }
}

impl Service<()> for &StaticKeystore {
    type Future = Ready<Result<Self::Response, Self::Error>>;
    type Response = JsonWebKeySet;
    type Error = Infallible;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        let rsa = self.rsa_keys.iter().map(|(kid, key)| {
            let pubkey = RsaPublicKey::from(key);
            JsonWebKey::new(pubkey.into())
                .with_kid(kid)
                .with_use(JsonWebKeyUse::Sig)
        });

        let es256 = self.es256_keys.iter().map(|(kid, key)| {
            let pubkey = ecdsa::VerifyingKey::from(key);
            JsonWebKey::new(pubkey.into())
                .with_kid(kid)
                .with_use(JsonWebKeyUse::Sig)
                .with_alg(JsonWebSignatureAlg::Es256)
        });

        let keys = rsa.chain(es256).collect();
        std::future::ready(Ok(JsonWebKeySet::new(keys)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_store() {
        let message = "this is the message to sign".as_bytes();
        let store = {
            let mut s = StaticKeystore::new();
            s.add_test_rsa_key().unwrap();
            s.add_test_ecdsa_key().unwrap();
            s
        };

        for alg in [
            JsonWebSignatureAlg::Rs256,
            JsonWebSignatureAlg::Rs384,
            JsonWebSignatureAlg::Rs512,
            JsonWebSignatureAlg::Es256,
        ] {
            let header = store.prepare_header(alg).await.unwrap();
            assert_eq!(header.alg(), alg);
            let signature = store.sign(&header, message).await.unwrap();
            store.verify(&header, message, &signature).await.unwrap();
        }
    }
}
