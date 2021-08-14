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

use headers::{authorization::Basic, Authorization, Header, HeaderValue};
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection};

use crate::{
    config::{OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
};

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

// TODO: move that somewhere else
pub fn with_typed_header<T: Header + Send + 'static>(
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::header::value(T::name().as_str()).and_then(decode_typed_header)
}

async fn decode_typed_header<T: Header>(header: HeaderValue) -> Result<T, Rejection> {
    let mut it = std::iter::once(&header);
    let decoded = T::decode(&mut it).wrap_error()?;
    Ok(decoded)
}

pub fn with_client_auth<T: DeserializeOwned + Send + 'static>(
    oauth2_config: &OAuth2Config,
) -> impl Filter<Extract = (ClientAuthentication, OAuth2ClientConfig, T), Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    // TODO: figure out the credentials *and then* authenticate the client
    let clients = oauth2_config.clients.clone();
    let client_secret_basic_filter = warp::any()
        .map(move || clients.clone())
        .and(with_typed_header())
        .and(warp::body::form())
        .and_then(client_secret_basic_auth)
        .untuple_one();

    let clients = oauth2_config.clients.clone();
    let client_post_filter = warp::any()
        .map(move || clients.clone())
        .and(warp::body::form())
        .and_then(client_post_auth)
        .untuple_one();

    client_secret_basic_filter.or(client_post_filter).unify()
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

fn authenticate_client(
    client_id: String,
    client_secret: Option<String>,
    clients: &[OAuth2ClientConfig],
) -> Result<&OAuth2ClientConfig, ClientAuthenticationError> {
    let client = clients
        .iter()
        .find(|client| client.client_id == client_id)
        .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
            client_id: client_id.clone(),
        })?;

    match (client_secret, client.client_secret.as_ref()) {
        (None, None) => Ok(client),
        (Some(ref given), Some(expected)) if given == expected => Ok(client),
        (Some(_), Some(_)) => Err(ClientAuthenticationError::ClientSecretMismatch { client_id }),
        (Some(_), None) => Err(ClientAuthenticationError::NoClientSecret { client_id }),
        (None, Some(_)) => Err(ClientAuthenticationError::ClientSecretRequired { client_id }),
    }
}

async fn client_secret_basic_auth<T>(
    clients: Vec<OAuth2ClientConfig>,
    auth: Authorization<Basic>,
    body: T,
) -> Result<(ClientAuthentication, OAuth2ClientConfig, T), Rejection> {
    let client_id = auth.0.username().to_string();
    let client_secret = auth.0.password().to_string();

    let client = authenticate_client(client_id, Some(client_secret), &clients)?;
    Ok((
        ClientAuthentication::ClientSecretBasic,
        client.clone(),
        body,
    ))
}

#[derive(Deserialize)]
struct ClientAuthForm<T> {
    client_id: String,
    client_secret: Option<String>,

    #[serde(flatten)]
    body: T,
}

async fn client_post_auth<T>(
    clients: Vec<OAuth2ClientConfig>,
    form: ClientAuthForm<T>,
) -> Result<(ClientAuthentication, OAuth2ClientConfig, T), Rejection> {
    let auth = if form.client_secret.is_some() {
        ClientAuthentication::ClientSecretPost
    } else {
        ClientAuthentication::None
    };

    let client = authenticate_client(form.client_id, form.client_secret, &clients)?;
    Ok((auth, client.clone(), form.body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth2_config() -> OAuth2Config {
        let mut config = OAuth2Config::default();
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
