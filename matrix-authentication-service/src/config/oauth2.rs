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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use url::Url;

use super::ConfigurationSection;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2ClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub client_secret: Option<String>,

    #[serde(default)]
    pub redirect_uris: Option<Vec<Url>>,
}

#[derive(Debug, Error)]
#[error("Invalid redirect URI")]
pub struct InvalidRedirectUriError;

impl OAuth2ClientConfig {
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        suggested_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        match (suggested_uri, &self.redirect_uris) {
            (None, None) => Err(InvalidRedirectUriError),
            (None, Some(redirect_uris)) => {
                redirect_uris.iter().next().ok_or(InvalidRedirectUriError)
            }
            (Some(suggested_uri), None) => Ok(suggested_uri),
            (Some(suggested_uri), Some(redirect_uris)) => {
                if redirect_uris.contains(suggested_uri) {
                    Ok(suggested_uri)
                } else {
                    Err(InvalidRedirectUriError)
                }
            }
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
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: default_oauth2_issuer(),
            clients: Vec::new(),
        }
    }
}

impl ConfigurationSection<'_> for OAuth2Config {
    fn path() -> &'static str {
        "oauth2"
    }

    fn generate() -> Self {
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
                    oauth2:
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
                Some(vec!["https://exemple.fr/callback".parse().unwrap()])
            );

            assert_eq!(config.clients[1].client_id, "world");
            assert_eq!(config.clients[1].redirect_uris, None);

            Ok(())
        });
    }
}
