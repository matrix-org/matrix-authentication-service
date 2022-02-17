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
use futures_util::future::Either;
use http::Request;
use mas_http::HttpServiceExt;
use mas_jose::{DynamicJwksStore, JsonWebKeySet, StaticJwksStore, VerifyingKeystore};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use tower::{BoxError, ServiceExt};
use url::Url;

use super::ConfigurationSection;

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    Jwks(JsonWebKeySet),
    JwksUri(Url),
}

impl JwksOrJwksUri {
    pub fn key_store(&self) -> Either<StaticJwksStore, DynamicJwksStore> {
        // Assert that the output is both a VerifyingKeystore and Send
        fn assert<T: Send + VerifyingKeystore>(t: T) -> T {
            t
        }

        let inner = match self {
            Self::Jwks(jwks) => Either::Left(StaticJwksStore::new(jwks.clone())),
            Self::JwksUri(uri) => {
                let uri = uri.clone();

                // TODO: get the client from somewhere else?
                let exporter = mas_http::client("fetch-jwks")
                    .json::<JsonWebKeySet>()
                    .map_request(move |_: ()| {
                        Request::builder()
                            .method("GET")
                            // TODO: change the Uri type in config to avoid reparsing here
                            .uri(uri.to_string())
                            .body(http_body::Empty::new())
                            .unwrap()
                    })
                    .map_response(http::Response::into_body)
                    .map_err(BoxError::from)
                    .boxed_clone();

                Either::Right(DynamicJwksStore::new(exporter))
            }
        };

        assert(inner)
    }
}

impl From<JsonWebKeySet> for JwksOrJwksUri {
    fn from(jwks: JsonWebKeySet) -> Self {
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
    /// signed by an asymetric key
    PrivateKeyJwt(JwksOrJwksUri),
}

/// An OAuth 2.0 client configuration
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientConfig {
    /// The client ID
    pub client_id: String,

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
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        suggested_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        suggested_uri.as_ref().map_or_else(
            || self.redirect_uris.get(0).ok_or(InvalidRedirectUriError),
            |suggested_uri| self.check_redirect_uri(suggested_uri),
        )
    }

    fn check_redirect_uri<'a>(
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

#[async_trait]
impl ConfigurationSection<'_> for ClientsConfig {
    fn path() -> &'static str {
        "clients"
    }

    #[tracing::instrument]
    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
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

            let config = ClientsConfig::load_from_file("config.yaml")?;

            assert_eq!(config.0.len(), 5);

            assert_eq!(config.0[0].client_id, "public");
            assert_eq!(
                config.0[0].redirect_uris,
                vec!["https://exemple.fr/callback".parse().unwrap()]
            );

            assert_eq!(config.0[1].client_id, "secret-basic");
            assert_eq!(config.0[1].redirect_uris, Vec::new());

            Ok(())
        });
    }
}
