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

use std::collections::HashSet;

use thiserror::Error;
use url::Url;

use crate::config::OAuth2ClientConfig;

#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    redirect_uris: Option<HashSet<Url>>,
}

#[derive(Debug, Error)]
#[error("Could not find client")]
pub struct ClientLookupError;

#[derive(Debug, Error)]
#[error("Invalid redirect URI")]
pub struct InvalidRedirectUriError;

impl Client {
    pub fn resolve_redirect_uri(
        &self,
        suggested_uri: Option<Url>,
    ) -> Result<Url, InvalidRedirectUriError> {
        match (suggested_uri, &self.redirect_uris) {
            (None, None) => Err(InvalidRedirectUriError),
            (None, Some(redirect_uris)) => redirect_uris
                .iter()
                .next()
                .cloned()
                .ok_or(InvalidRedirectUriError),
            (Some(suggested_uri), None) => Ok(suggested_uri),
            (Some(suggested_uri), Some(redirect_uris)) => {
                if redirect_uris.contains(&suggested_uri) {
                    Ok(suggested_uri)
                } else {
                    Err(InvalidRedirectUriError)
                }
            }
        }
    }
}

impl<T> super::Storage<T> {
    pub fn with_static_clients(mut self, clients: &[OAuth2ClientConfig]) -> Self {
        let storage = &mut self.clients;
        for config in clients {
            let redirect_uris = config
                .redirect_uris
                .as_ref()
                .map(|uris| uris.iter().cloned().collect());
            let client_id = config.client_id.clone();

            let client = Client {
                client_id: client_id.clone(),
                redirect_uris,
            };

            // TODO: we could warn about duplicate clients here
            storage.insert(client_id, client);
        }

        self
    }

    pub async fn lookup_client(&self, client_id: &str) -> Result<Client, ClientLookupError> {
        self.clients
            .get(client_id)
            .cloned()
            .ok_or(ClientLookupError)
    }
}
