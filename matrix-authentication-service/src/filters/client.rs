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

use headers::{authorization::Basic, Authorization};
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection};

use super::headers::with_typed_header;
use crate::config::{OAuth2ClientConfig, OAuth2Config};

#[derive(Debug, PartialEq, Eq)]
pub enum ClientAuthentication {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

impl ClientAuthentication {
    pub fn public(&self) -> bool {
        matches!(self, &Self::None)
    }
}

pub fn with_client_auth<T: DeserializeOwned + Send + 'static>(
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (ClientAuthentication, OAuth2ClientConfig, T), Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    // First, extract the client credentials
    let credentials = with_typed_header()
        .and(warp::body::form())
        // Either from the "Authorization" header
        .map(|auth: Authorization<Basic>, body: T| {
            let client_id = auth.0.username().to_string();
            let client_secret = Some(auth.0.password().to_string());
            (
                ClientAuthentication::ClientSecretBasic,
                client_id,
                client_secret,
                body,
            )
        })
        // Or from the form body
        .or(warp::body::form().map(|form: ClientAuthForm<T>| {
            let ClientAuthForm {
                client_id,
                client_secret,
                body,
            } = form;
            let auth_type = if client_secret.is_some() {
                ClientAuthentication::ClientSecretPost
            } else {
                ClientAuthentication::None
            };
            (auth_type, client_id, client_secret, body)
        }))
        .unify()
        .untuple_one();

    let clients = oauth2_config.clients.clone();
    warp::any()
        .map(move || clients.clone())
        .and(credentials)
        .and_then(authenticate_client)
        .untuple_one()
}

#[derive(Error, Debug)]
enum ClientAuthenticationError {
    #[error("no client secret found for client {client_id:?}")]
    NoClientSecret { client_id: String },

    #[error("wrong client secret for client {client_id:?}")]
    ClientSecretMismatch { client_id: String },

    #[error("could not find client {client_id:?}")]
    ClientNotFound { client_id: String },

    #[error("client secret required for client {client_id:?}")]
    ClientSecretRequired { client_id: String },
}

impl Reject for ClientAuthenticationError {}

async fn authenticate_client<T>(
    clients: Vec<OAuth2ClientConfig>,
    auth_type: ClientAuthentication,
    client_id: String,
    client_secret: Option<String>,
    body: T,
) -> Result<(ClientAuthentication, OAuth2ClientConfig, T), Rejection> {
    let client = clients
        .iter()
        .find(|client| client.client_id == client_id)
        .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
            client_id: client_id.to_string(),
        })?;

    let client = match (client_secret, client.client_secret.as_ref()) {
        (None, None) => Ok(client),
        (Some(ref given), Some(expected)) if given == expected => Ok(client),
        (Some(_), Some(_)) => Err(ClientAuthenticationError::ClientSecretMismatch { client_id }),
        (Some(_), None) => Err(ClientAuthenticationError::NoClientSecret { client_id }),
        (None, Some(_)) => Err(ClientAuthenticationError::ClientSecretRequired { client_id }),
    }?;

    Ok((auth_type, client.clone(), body))
}

#[derive(Deserialize)]
struct ClientAuthForm<T> {
    client_id: String,
    client_secret: Option<String>,

    #[serde(flatten)]
    body: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth2_config() -> OAuth2Config {
        let mut config = OAuth2Config::test();
        config.clients.push(OAuth2ClientConfig {
            client_id: "public".to_string(),
            client_secret: None,
            redirect_uris: None,
        });
        config.clients.push(OAuth2ClientConfig {
            client_id: "confidential".to_string(),
            client_secret: Some("secret".to_string()),
            redirect_uris: None,
        });
        config
    }

    #[derive(Deserialize)]
    struct Form {
        foo: String,
        bar: String,
    }

    #[tokio::test]
    async fn client_secret_post() {
        let filter = with_client_auth::<Form>(&oauth2_config());

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .body("client_id=confidential&client_secret=secret&foo=baz&bar=foobar")
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthentication::ClientSecretPost);
        assert_eq!(client.client_id, "confidential");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn client_secret_basic() {
        let filter = with_client_auth::<Form>(&oauth2_config());

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header("Authorization", "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
            .body("foo=baz&bar=foobar")
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthentication::ClientSecretBasic);
        assert_eq!(client.client_id, "confidential");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn none() {
        let filter = with_client_auth::<Form>(&oauth2_config());

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .body("client_id=public&foo=baz&bar=foobar")
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthentication::None);
        assert_eq!(client.client_id, "public");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }
}
