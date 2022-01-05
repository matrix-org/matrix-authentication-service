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

use anyhow::Context;
use async_trait::async_trait;
use mas_jose::{JsonWebKeySet, StaticJwksStore, StaticKeystore};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use tokio::task;
use tracing::info;
use url::Url;

use super::ConfigurationSection;

#[derive(JsonSchema, Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    r#type: KeyType,
    key: String,
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    Jwks(JsonWebKeySet),
    JwksUri(Url),
}

impl JwksOrJwksUri {
    pub fn key_store(&self) -> StaticJwksStore {
        let jwks = match self {
            Self::Jwks(jwks) => jwks.clone(),
            Self::JwksUri(_) => unimplemented!("jwks_uri are not implemented yet"),
        };

        StaticJwksStore::new(jwks)
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "client_auth_method", rename_all = "snake_case")]
pub enum OAuth2ClientAuthMethodConfig {
    None,
    ClientSecretBasic { client_secret: String },
    ClientSecretPost { client_secret: String },
    ClientSecretJwt { client_secret: String },
    PrivateKeyJwt(JwksOrJwksUri),
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2ClientConfig {
    pub client_id: String,

    #[serde(flatten)]
    pub client_auth_method: OAuth2ClientAuthMethodConfig,

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

    #[serde(default)]
    pub keys: Vec<KeyConfig>,
}

impl OAuth2Config {
    #[must_use]
    pub fn discovery_url(&self) -> Url {
        self.issuer
            .join(".well-known/openid-configuration")
            .expect("could not build discovery url")
    }

    pub fn key_store(&self) -> anyhow::Result<StaticKeystore> {
        let mut store = StaticKeystore::new();

        for key in &self.keys {
            match key.r#type {
                KeyType::Ecdsa => {
                    let key = p256::SecretKey::from_pkcs8_pem(&key.key)?;
                    store.add_ecdsa_key(key.into())?;
                }
                KeyType::Rsa => {
                    let key = rsa::RsaPrivateKey::from_pkcs1_pem(&key.key)?;
                    store.add_rsa_key(key)?;
                }
            }
        }

        Ok(store)
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
        })
        .await
        .context("could not join blocking task")??;
        let rsa_key = KeyConfig {
            r#type: KeyType::Rsa,
            key: rsa_key.to_pkcs1_pem(pkcs8::LineEnding::LF)?.to_string(),
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
            key: ecdsa_key.to_pkcs8_pem(pkcs8::LineEnding::LF)?.to_string(),
        };

        Ok(Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
            keys: vec![rsa_key, ecdsa_key],
        })
    }

    fn test() -> Self {
        let rsa_key = KeyConfig {
            r#type: KeyType::Rsa,
            key: indoc::indoc! {r#"
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
        };
        let ecdsa_key = KeyConfig {
            r#type: KeyType::Ecdsa,
            key: indoc::indoc! {r#"
              -----BEGIN PRIVATE KEY-----
              MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
              NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
              OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
              -----END PRIVATE KEY-----
            "#}
            .to_string(),
        };

        Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
            keys: vec![rsa_key, ecdsa_key],
        }
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
                        - client_id: public
                          client_auth_method: none
                          redirect_uris:
                            - https://exemple.fr/callback

                        - client_id: secret-basic
                          client_auth_method: client_secret_basic
                          client_secret: hello

                        - client_id: secret-post
                          client_auth_method: client_secret_post
                          client_secret: hello

                        - client_id: secret-jwk
                          client_auth_method: client_secret_jwt
                          client_secret: hello

                        - client_id: jwks
                          client_auth_method: private_key_jwt
                          jwks:
                            keys:
                            - kid: "03e84aed4ef4431014e8617567864c4efaaaede9"
                              kty: "RSA"
                              alg: "RS256"
                              use: "sig"
                              e: "AQAB"
                              n: "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw"

                            - kid: "d01c1abe249269f72ef7ca2613a86c9f05e59567"
                              kty: "RSA"
                              alg: "RS256"
                              use: "sig"
                              e: "AQAB"
                              n: "0hukqytPwrj1RbMYhYoepCi3CN5k7DwYkTe_Cmb7cP9_qv4ok78KdvFXt5AnQxCRwBD7-qTNkkfMWO2RxUMBdQD0ED6tsSb1n5dp0XY8dSWiBDCX8f6Hr-KolOpvMLZKRy01HdAWcM6RoL9ikbjYHUEW1C8IJnw3MzVHkpKFDL354aptdNLaAdTCBvKzU9WpXo10g-5ctzSlWWjQuecLMQ4G1mNdsR1LHhUENEnOvgT8cDkX0fJzLbEbyBYkdMgKggyVPEB1bg6evG4fTKawgnf0IDSPxIU-wdS9wdSP9ZCJJPLi5CEp-6t6rE_sb2dGcnzjCGlembC57VwpkUvyMw"
                "#,
            )?;

            let config = OAuth2Config::load_from_file("config.yaml")?;

            assert_eq!(config.issuer, "https://example.com".parse().unwrap());
            assert_eq!(config.clients.len(), 5);

            assert_eq!(config.clients[0].client_id, "public");
            assert_eq!(
                config.clients[0].redirect_uris,
                vec!["https://exemple.fr/callback".parse().unwrap()]
            );

            assert_eq!(config.clients[1].client_id, "secret-basic");
            assert_eq!(config.clients[1].redirect_uris, Vec::new());

            Ok(())
        });
    }
}
