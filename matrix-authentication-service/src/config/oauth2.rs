// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::convert::TryFrom;

use anyhow::Context;
use async_trait::async_trait;
use jwt_compact::{
    alg::{self, StrongAlg, StrongKey},
    jwk::JsonWebKey,
    AlgorithmExt, Claims, Header,
};
use pkcs8::{FromPrivateKey, ToPrivateKey};
use rsa::RsaPrivateKey;
use schemars::JsonSchema;
use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use serde_with::skip_serializing_none;
use thiserror::Error;
use tokio::task;
use tracing::info;
use url::Url;

use super::ConfigurationSection;

// TODO: a lot of the signing logic should go out somewhere else

const RS256: StrongAlg<alg::Rsa> = StrongAlg(alg::Rsa::rs256());

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Rs256,
    Es256k,
}

#[derive(Serialize, Clone)]
pub struct Jwk {
    kid: String,
    alg: Algorithm,

    #[serde(flatten)]
    inner: serde_json::Value,
}

#[derive(Serialize, Clone)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct KeySet(Vec<Key>);

impl KeySet {
    pub fn to_public_jwks(&self) -> Jwks {
        let keys = self.0.iter().map(Key::to_public_jwk).collect();
        Jwks { keys }
    }

    #[tracing::instrument(err)]
    pub async fn token<T>(
        &self,
        alg: Algorithm,
        header: Header,
        claims: Claims<T>,
    ) -> anyhow::Result<String>
    where
        T: std::fmt::Debug + Serialize + Send + Sync + 'static,
    {
        match alg {
            Algorithm::Rs256 => {
                let (kid, key) = self
                    .0
                    .iter()
                    .find_map(Key::rsa)
                    .context("could not find RSA key")?;
                let header = header.with_key_id(kid);

                // TODO: store them as strong keys
                let key = StrongKey::try_from(key.clone())?;
                task::spawn_blocking(move || {
                    RS256
                        .token(header, &claims, &key)
                        .context("failed to sign token")
                })
                .await?
            }
            Algorithm::Es256k => {
                // TODO: make this const with lazy_static?
                let es256k: alg::Es256k = alg::Es256k::default();
                let (kid, key) = self
                    .0
                    .iter()
                    .find_map(Key::ecdsa)
                    .context("could not find ECDSA key")?;
                let key = k256::ecdsa::SigningKey::from(key);
                let header = header.with_key_id(kid);
                // TODO: use StrongAlg

                task::spawn_blocking(move || {
                    es256k
                        .token(header, &claims, &key)
                        .context("failed to sign token")
                })
                .await?
            }
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Key {
    Rsa { key: RsaPrivateKey, kid: String },
    Ecdsa { key: k256::SecretKey, kid: String },
}

impl Key {
    fn from_ecdsa(key: k256::SecretKey) -> Self {
        // TODO: hash the key and use as KID
        let kid = String::from("ecdsa-kid");
        Self::Ecdsa { kid, key }
    }

    fn from_ecdsa_pem(key: &str) -> anyhow::Result<Self> {
        let key = k256::SecretKey::from_pkcs8_pem(key)?;
        Ok(Self::from_ecdsa(key))
    }

    fn from_rsa(key: RsaPrivateKey) -> Self {
        // TODO: hash the key and use as KID
        let kid = String::from("rsa-kid");
        Self::Rsa { kid, key }
    }

    fn from_rsa_pem(key: &str) -> anyhow::Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_pem(key)?;
        Ok(Self::from_rsa(key))
    }

    fn to_public_jwk(&self) -> Jwk {
        match self {
            Key::Rsa { key, kid } => {
                let pubkey = key.to_public_key();
                let inner = JsonWebKey::from(&pubkey);
                let inner = serde_json::to_value(&inner).unwrap();
                let kid = kid.to_string();
                let alg = Algorithm::Rs256;
                Jwk { kid, alg, inner }
            }
            Key::Ecdsa { key, kid } => {
                let pubkey = k256::ecdsa::VerifyingKey::from(key.public_key());
                let inner = JsonWebKey::from(&pubkey);
                let inner = serde_json::to_value(&inner).unwrap();
                let kid = kid.to_string();
                let alg = Algorithm::Es256k;
                Jwk { kid, alg, inner }
            }
        }
    }

    fn rsa(&self) -> Option<(&str, &RsaPrivateKey)> {
        match self {
            Key::Rsa { key, kid } => Some((kid, key)),
            _ => None,
        }
    }

    fn ecdsa(&self) -> Option<(&str, &k256::SecretKey)> {
        match self {
            Key::Ecdsa { key, kid } => Some((kid, key)),
            _ => None,
        }
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_struct("Key", 2)?;
        match self {
            Key::Rsa { key, kid: _ } => {
                map.serialize_field("type", "rsa")?;
                let pem = key.to_pkcs8_pem().map_err(serde::ser::Error::custom)?;
                map.serialize_field("key", pem.as_str())?;
            }
            Key::Ecdsa { key, kid: _ } => {
                map.serialize_field("type", "ecdsa")?;
                let pem = key.to_pkcs8_pem().map_err(serde::ser::Error::custom)?;
                map.serialize_field("key", pem.as_str())?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Type,
            Key,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum KeyType {
            Rsa,
            Ecdsa,
        }

        struct KeyVisitor;

        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Key")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Key, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_type = None;
                let mut key_key = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if key_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("type"));
                            }
                            key_type = Some(map.next_value()?);
                        }
                        Field::Key => {
                            if key_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("key"));
                            }
                            key_key = Some(map.next_value()?);
                        }
                    }
                }
                let key_type: KeyType =
                    key_type.ok_or_else(|| serde::de::Error::missing_field("type"))?;
                let key_key: String =
                    key_key.ok_or_else(|| serde::de::Error::missing_field("key"))?;

                match key_type {
                    KeyType::Rsa => Key::from_rsa_pem(&key_key).map_err(serde::de::Error::custom),
                    KeyType::Ecdsa => {
                        Key::from_ecdsa_pem(&key_key).map_err(serde::de::Error::custom)
                    }
                }
            }
        }

        deserializer.deserialize_struct("Key", &["type", "key"], KeyVisitor)
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2ClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub client_secret: Option<String>,

    #[serde(default)]
    pub redirect_uris: Vec<Url>,
}

#[derive(Debug, Error)]
#[error("Invalid redirect URI")]
pub struct InvalidRedirectUriError;

impl OAuth2ClientConfig {
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        suggested_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        suggested_uri.as_ref().map_or_else(
            || self.redirect_uris.get(0).ok_or(InvalidRedirectUriError),
            |suggested_uri| self.check_redirect_uri(suggested_uri),
        )
    }

    pub fn check_redirect_uri<'a>(
        &self,
        redirect_uri: &'a Url,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        if self.redirect_uris.contains(redirect_uri) {
            Ok(redirect_uri)
        } else {
            Err(InvalidRedirectUriError)
        }
    }
}

fn default_oauth2_issuer() -> Url {
    "http://[::]:8080".parse().unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2Config {
    #[serde(default = "default_oauth2_issuer")]
    pub issuer: Url,

    #[serde(default)]
    pub clients: Vec<OAuth2ClientConfig>,

    #[schemars(with = "Vec<String>")] // TODO: this is a lie
    pub keys: KeySet,
}

impl OAuth2Config {
    pub fn discovery_url(&self) -> Url {
        self.issuer
            .join(".well-known/openid-configuration")
            .expect("could not build discovery url")
    }

    #[cfg(test)]
    pub fn test() -> Self {
        let rsa_key = Key::from_rsa_pem(indoc::indoc! {r#"
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
        "#})
        .unwrap();
        let ecdsa_key = Key::from_rsa_pem(indoc::indoc! {r#"
          -----BEGIN PRIVATE KEY-----
          MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
          NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
          OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
          -----END PRIVATE KEY-----
        "#})
        .unwrap();

        Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
            keys: KeySet(vec![rsa_key, ecdsa_key]),
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for OAuth2Config {
    fn path() -> &'static str {
        "oauth2"
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
        });

        let span = tracing::info_span!("ecdsa");
        let ecdsa_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let rng = rand::thread_rng();
            let ret = k256::SecretKey::random(rng);
            info!("Done generating ECDSA key");
            ret
        });

        let (ecdsa_key, rsa_key) = tokio::join!(ecdsa_key, rsa_key);
        let rsa_key = rsa_key.context("could not join blocking task")??;
        let ecdsa_key = ecdsa_key.context("could not join blocking task")?;

        Ok(Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
            keys: KeySet(vec![Key::from_rsa(rsa_key), Key::from_ecdsa(ecdsa_key)]),
        })
    }
}

#[cfg(test)]
mod tests {
    use figment::Jail;

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    oauth2:
                      keys: 
                        - type: rsa
                          key: |
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
                        - type: ecdsa
                          key: |
                            -----BEGIN PRIVATE KEY-----
                            MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                            NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                            OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                            -----END PRIVATE KEY-----
                      issuer: https://example.com
                      clients:
                        - client_id: hello
                          redirect_uris:
                            - https://exemple.fr/callback
                        - client_id: world
                "#,
            )?;

            let config = OAuth2Config::load_from_file("config.yaml")?;

            assert_eq!(config.issuer, "https://example.com".parse().unwrap());
            assert_eq!(config.clients.len(), 2);

            assert_eq!(config.clients[0].client_id, "hello");
            assert_eq!(
                config.clients[0].redirect_uris,
                vec!["https://exemple.fr/callback".parse().unwrap()]
            );

            assert_eq!(config.clients[1].client_id, "world");
            assert_eq!(config.clients[1].redirect_uris, Vec::new());

            Ok(())
        });
    }
}
