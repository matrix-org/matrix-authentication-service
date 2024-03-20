// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_jose::jwk::PublicJsonWebKeySet;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use super::ConfigurationSection;

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    Jwks(PublicJsonWebKeySet),
    JwksUri(Url),
}

impl From<PublicJsonWebKeySet> for JwksOrJwksUri {
    fn from(jwks: PublicJsonWebKeySet) -> Self {
        Self::Jwks(jwks)
    }
}

/// Authentication method used by clients
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "client_auth_method", rename_all = "snake_case")]
pub enum ClientAuthMethodConfig {
    /// `none`: No authentication
    None,

    /// `client_secret_basic`: `client_id` and `client_secret` used as basic
    /// authorization credentials
    ClientSecretBasic {
        /// The client secret
        client_secret: String,
    },

    /// `client_secret_post`: `client_id` and `client_secret` sent in the
    /// request body
    ClientSecretPost {
        /// The client secret
        client_secret: String,
    },

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed using the `client_secret`
    ClientSecretJwt {
        /// The client secret
        client_secret: String,
    },

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed by an asymmetric key
    PrivateKeyJwt(JwksOrJwksUri),
}

/// An OAuth 2.0 client configuration
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientConfig {
    /// The client ID
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub client_id: Ulid,

    /// Authentication method used for this client
    #[serde(flatten)]
    pub client_auth_method: ClientAuthMethodConfig,

    /// List of allowed redirect URIs
    #[serde(default)]
    pub redirect_uris: Vec<Url>,
}

#[derive(Debug, Error)]
#[error("Invalid redirect URI")]
pub struct InvalidRedirectUriError;

impl ClientConfig {
    #[doc(hidden)]
    #[must_use]
    pub fn client_secret(&self) -> Option<&str> {
        match &self.client_auth_method {
            ClientAuthMethodConfig::ClientSecretPost { client_secret }
            | ClientAuthMethodConfig::ClientSecretBasic { client_secret }
            | ClientAuthMethodConfig::ClientSecretJwt { client_secret } => Some(client_secret),
            _ => None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn client_auth_method(&self) -> OAuthClientAuthenticationMethod {
        match &self.client_auth_method {
            ClientAuthMethodConfig::None => OAuthClientAuthenticationMethod::None,
            ClientAuthMethodConfig::ClientSecretBasic { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretBasic
            }
            ClientAuthMethodConfig::ClientSecretPost { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretPost
            }
            ClientAuthMethodConfig::ClientSecretJwt { .. } => {
                OAuthClientAuthenticationMethod::ClientSecretJwt
            }
            ClientAuthMethodConfig::PrivateKeyJwt(_) => {
                OAuthClientAuthenticationMethod::PrivateKeyJwt
            }
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn jwks(&self) -> Option<&PublicJsonWebKeySet> {
        match &self.client_auth_method {
            ClientAuthMethodConfig::PrivateKeyJwt(JwksOrJwksUri::Jwks(jwks)) => Some(jwks),
            _ => None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn jwks_uri(&self) -> Option<&Url> {
        match &self.client_auth_method {
            ClientAuthMethodConfig::PrivateKeyJwt(JwksOrJwksUri::JwksUri(jwks_uri)) => {
                Some(jwks_uri)
            }
            _ => None,
        }
    }
}

/// List of OAuth 2.0/OIDC clients config
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ClientsConfig(Vec<ClientConfig>);

impl Deref for ClientsConfig {
    type Target = Vec<ClientConfig>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClientsConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for ClientsConfig {
    type Item = ClientConfig;
    type IntoIter = std::vec::IntoIter<ClientConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[async_trait]
impl ConfigurationSection for ClientsConfig {
    fn path() -> &'static str {
        "clients"
    }

    async fn generate<R>(_rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use figment::{
        providers::{Format, Yaml},
        Figment, Jail,
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                  clients:
                    - client_id: 01GFWR28C4KNE04WG3HKXB7C9R
                      client_auth_method: none
                      redirect_uris:
                        - https://exemple.fr/callback

                    - client_id: 01GFWR32NCQ12B8Z0J8CPXRRB6
                      client_auth_method: client_secret_basic
                      client_secret: hello

                    - client_id: 01GFWR3WHR93Y5HK389H28VHZ9
                      client_auth_method: client_secret_post
                      client_secret: hello

                    - client_id: 01GFWR43R2ZZ8HX9CVBNW9TJWG
                      client_auth_method: client_secret_jwt
                      client_secret: hello

                    - client_id: 01GFWR4BNFDCC4QDG6AMSP1VRR
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

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<ClientsConfig>("clients")?;

            assert_eq!(config.0.len(), 5);

            assert_eq!(
                config.0[0].client_id,
                Ulid::from_str("01GFWR28C4KNE04WG3HKXB7C9R").unwrap()
            );
            assert_eq!(
                config.0[0].redirect_uris,
                vec!["https://exemple.fr/callback".parse().unwrap()]
            );

            assert_eq!(
                config.0[1].client_id,
                Ulid::from_str("01GFWR32NCQ12B8Z0J8CPXRRB6").unwrap()
            );
            assert_eq!(config.0[1].redirect_uris, Vec::new());

            Ok(())
        });
    }
}
