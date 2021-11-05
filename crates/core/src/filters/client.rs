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

//! Handle client authentication

use std::borrow::Cow;

use chrono::{Duration, Utc};
use headers::{authorization::Basic, Authorization};
use jwt_compact::{
    alg::{Hs256, Hs256Key, Hs384, Hs384Key, Hs512, Hs512Key},
    Algorithm, AlgorithmExt, AlgorithmSignature, TimeOptions, Token, UntrustedToken,
};
use oauth2_types::requests::ClientAuthenticationMethod;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection};

use super::headers::typed_header;
use crate::{
    config::{OAuth2ClientConfig, OAuth2Config},
    errors::WrapError,
};

/// Protect an enpoint with client authentication
#[must_use]
pub fn client_authentication<T: DeserializeOwned + Send + 'static>(
    oauth2_config: &OAuth2Config,
    audience: String,
) -> impl Filter<Extract = (ClientAuthenticationMethod, OAuth2ClientConfig, T), Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    // First, extract the client credentials
    let credentials = typed_header()
        .and(warp::body::form())
        // Either from the "Authorization" header
        .map(|auth: Authorization<Basic>, body: T| {
            let client_id = auth.0.username().to_string();
            let client_secret = Some(auth.0.password().to_string());
            (
                ClientCredentials::Pair {
                    via: CredentialsVia::AuthorizationHeader,
                    client_id,
                    client_secret,
                },
                body,
            )
        })
        // Or from the form body
        .or(warp::body::form().map(|form: ClientAuthForm<T>| {
            let ClientAuthForm { credentials, body } = form;

            (credentials, body)
        }))
        .unify()
        .untuple_one();

    let clients = oauth2_config.clients.clone();
    warp::any()
        .map(move || clients.clone())
        .and(warp::any().map(move || audience.clone()))
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

    #[error("wrong audience in client assertion: expected {expected:?}, got {got:?}")]
    AudienceMismatch { expected: String, got: String },

    #[error("invalid client assertion")]
    InvalidAssertion,
}

impl Reject for ClientAuthenticationError {}

#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
struct ClientAssertionClaims {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "aud")]
    audience: String,
    // TODO: use the JTI and ensure it is only used once
    #[serde(default, rename = "jti")]
    jwt_id: Option<String>,
}

struct UnsignedSignature(Vec<u8>);
impl AlgorithmSignature for UnsignedSignature {
    fn try_from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        Ok(Self(slice.to_vec()))
    }

    fn as_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
}

struct Unsigned<'a>(&'a str);
impl<'a> Algorithm for Unsigned<'a> {
    type SigningKey = ();

    type VerifyingKey = ();

    type Signature = UnsignedSignature;

    fn name(&self) -> std::borrow::Cow<'static, str> {
        Cow::Owned(self.0.to_string())
    }

    fn sign(&self, _signing_key: &Self::SigningKey, _message: &[u8]) -> Self::Signature {
        UnsignedSignature(Vec::new())
    }

    fn verify_signature(
        &self,
        _signature: &Self::Signature,
        _verifying_key: &Self::VerifyingKey,
        _message: &[u8],
    ) -> bool {
        true
    }
}

fn verify_token(
    untrusted_token: &UntrustedToken,
    key: &str,
) -> anyhow::Result<Token<ClientAssertionClaims>> {
    match untrusted_token.algorithm() {
        "HS256" => {
            let key = Hs256Key::new(key);
            let token = Hs256.validate_integrity(untrusted_token, &key)?;
            Ok(token)
        }
        "HS384" => {
            let key = Hs384Key::new(key);
            let token = Hs384.validate_integrity(untrusted_token, &key)?;
            Ok(token)
        }
        "HS512" => {
            let key = Hs512Key::new(key);
            let token = Hs512.validate_integrity(untrusted_token, &key)?;
            Ok(token)
        }
        alg => anyhow::bail!("unsupported signing algorithm {}", alg),
    }
}

async fn authenticate_client<T>(
    clients: Vec<OAuth2ClientConfig>,
    audience: String,
    credentials: ClientCredentials,
    body: T,
) -> Result<(ClientAuthenticationMethod, OAuth2ClientConfig, T), Rejection> {
    let auth_type = credentials.authentication_type();
    let client = match credentials {
        ClientCredentials::Pair {
            client_id,
            client_secret,
            ..
        } => {
            let client = clients
                .iter()
                .find(|client| client.client_id == client_id)
                .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
                    client_id: client_id.to_string(),
                })?;

            match (client_secret, client.client_secret.as_ref()) {
                (None, None) => Ok(client),
                (Some(ref given), Some(expected)) if given == expected => Ok(client),
                (Some(_), Some(_)) => {
                    Err(ClientAuthenticationError::ClientSecretMismatch { client_id })
                }
                (Some(_), None) => Err(ClientAuthenticationError::NoClientSecret { client_id }),
                (None, Some(_)) => {
                    Err(ClientAuthenticationError::ClientSecretRequired { client_id })
                }
            }
        }
        ClientCredentials::Assertion {
            client_id,
            client_assertion_type: ClientAssertionType::JwtBearer,
            client_assertion,
        } => {
            let untrusted_token = UntrustedToken::new(&client_assertion).wrap_error()?;

            // client_id might have been passed as parameter. If not, it should be inferred
            // from the token, as per rfc7521 sec. 4.2
            // TODO: this is not a pretty way to do it
            let client_id = client_id
                .ok_or(()) // Dumb error type
                .or_else(|()| {
                    let alg = Unsigned(untrusted_token.algorithm());
                    // We need to deserialize the token once without verifying the signature to get
                    // the client_id
                    let token: Token<ClientAssertionClaims> =
                        alg.validate_integrity(&untrusted_token, &())?;

                    Ok::<_, anyhow::Error>(token.claims().custom.subject.clone())
                })
                .wrap_error()?;

            let client = clients
                .iter()
                .find(|client| client.client_id == client_id)
                .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
                    client_id: client_id.to_string(),
                })?;

            if let Some(client_secret) = &client.client_secret {
                let token = verify_token(&untrusted_token, client_secret).wrap_error()?;

                let time_options = TimeOptions::new(Duration::minutes(1), Utc::now);

                // rfc7523 sec. 3.4: expiration must be set and validated
                let claims = token
                    .claims()
                    .validate_expiration(&time_options)
                    .wrap_error()?;

                // rfc7523 sec. 3.5: "not before" can be set and must be validated if present
                if claims.not_before.is_some() {
                    claims.validate_maturity(&time_options).wrap_error()?;
                }

                // rfc7523 sec. 3.3: the audience is the URL being called
                if claims.custom.audience != audience {
                    Err(ClientAuthenticationError::AudienceMismatch {
                        expected: audience,
                        got: claims.custom.audience.clone(),
                    })
                // rfc7523 sec. 3.1 & 3.2: both the issuer and the subject must
                // match the client_id
                } else if claims.custom.issuer != claims.custom.subject
                    || claims.custom.issuer != client_id
                {
                    Err(ClientAuthenticationError::InvalidAssertion)
                } else {
                    Ok(client)
                }
            } else {
                Err(ClientAuthenticationError::ClientSecretRequired {
                    client_id: client_id.to_string(),
                })
            }
        }
    }?;

    Ok((auth_type, client.clone(), body))
}

#[derive(Deserialize)]
enum ClientAssertionType {
    #[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
    JwtBearer,
}

enum CredentialsVia {
    FormBody,
    AuthorizationHeader,
}

impl Default for CredentialsVia {
    fn default() -> Self {
        Self::FormBody
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientCredentials {
    // Order here is important: serde tries to deserialize enum variants in order, so if "Pair"
    // was before "Assertion", a client_assertion with a client_id would match the "Pair"
    // variant first
    Assertion {
        client_id: Option<String>,
        client_assertion_type: ClientAssertionType,
        client_assertion: String,
    },
    Pair {
        #[serde(skip)]
        via: CredentialsVia,
        client_id: String,
        client_secret: Option<String>,
    },
}

impl ClientCredentials {
    fn authentication_type(&self) -> ClientAuthenticationMethod {
        match self {
            ClientCredentials::Pair {
                via: CredentialsVia::FormBody,
                client_secret: None,
                ..
            } => ClientAuthenticationMethod::None,
            ClientCredentials::Pair {
                via: CredentialsVia::FormBody,
                client_secret: Some(_),
                ..
            } => ClientAuthenticationMethod::ClientSecretPost,
            ClientCredentials::Pair {
                via: CredentialsVia::AuthorizationHeader,
                ..
            } => ClientAuthenticationMethod::ClientSecretBasic,
            ClientCredentials::Assertion { .. } => ClientAuthenticationMethod::ClientSecretJwt,
        }
    }
}

#[derive(Deserialize)]
struct ClientAuthForm<T> {
    #[serde(flatten)]
    credentials: ClientCredentials,

    #[serde(flatten)]
    body: T,
}

#[cfg(test)]
mod tests {
    use headers::authorization::Credentials;
    use jwt_compact::{Claims, Header};
    use mas_config::ConfigurationSection;
    use serde_json::json;

    use super::*;

    // Long client_secret to support it as a HS512 key
    const CLIENT_SECRET: &str = "leek2zaeyeb8thai7piehea3vah6ool9oanin9aeraThuci9EeghaekaiD1upe4Quoh7xeMae2meitohj0Waaveiwaorah1yazohr6Vae7iebeiRaWene5IeWeeciezu";

    fn oauth2_config() -> OAuth2Config {
        let mut config = OAuth2Config::test();
        config.clients.push(OAuth2ClientConfig {
            client_id: "public".to_string(),
            client_secret: None,
            redirect_uris: Vec::new(),
        });
        config.clients.push(OAuth2ClientConfig {
            client_id: "confidential".to_string(),
            client_secret: Some(CLIENT_SECRET.to_string()),
            redirect_uris: Vec::new(),
        });
        config.clients.push(OAuth2ClientConfig {
            client_id: "confidential-2".to_string(),
            client_secret: Some(CLIENT_SECRET.to_string()),
            redirect_uris: Vec::new(),
        });
        config
    }

    #[derive(Deserialize)]
    struct Form {
        foo: String,
        bar: String,
    }

    #[tokio::test]
    async fn client_secret_jwt_hs256() {
        client_secret_jwt::<'_, Hs256>().await;
    }

    #[tokio::test]
    async fn client_secret_jwt_hs384() {
        client_secret_jwt::<'_, Hs384>().await;
    }

    #[tokio::test]
    async fn client_secret_jwt_hs512() {
        client_secret_jwt::<'_, Hs512>().await;
    }

    async fn client_secret_jwt<'k, A>()
    where
        A: Algorithm + Default,
        A::SigningKey: From<&'k [u8]>,
    {
        let audience = "https://example.com/token".to_string();
        let filter = client_authentication::<Form>(&oauth2_config(), audience.clone());
        let time_options = TimeOptions::default();

        let key = A::SigningKey::from(CLIENT_SECRET.as_bytes());
        let alg = A::default();
        let header = Header::default();
        let claims = Claims::new(ClientAssertionClaims {
            issuer: "confidential".to_string(),
            subject: "confidential".to_string(),
            audience,
            jwt_id: None,
        })
        .set_duration_and_issuance(&time_options, Duration::seconds(15));

        // TODO: test failing cases
        //  - expired token
        //  - "not before" in the future
        //  - subject/issuer mismatch
        //  - audience mismatch
        //  - wrong secret/signature

        let token = alg
            .token(header, &claims, &key)
            .expect("could not sign token");

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_id": "confidential",
                "client_assertion": token,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthenticationMethod::ClientSecretJwt);
        assert_eq!(client.client_id, "confidential");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");

        // Without client_id
        let res = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_assertion": token,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await;
        assert!(res.is_ok());

        // client_id mismatch
        let res = warp::test::request()
            .method("POST")
            .body(serde_urlencoded::to_string(json!({
                "client_id": "confidential-2",
                "client_assertion": token,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn client_secret_post() {
        let filter = client_authentication::<Form>(
            &oauth2_config(),
            "https://example.com/token".to_string(),
        );

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header(
                "Content-Type",
                mime::APPLICATION_WWW_FORM_URLENCODED.to_string(),
            )
            .body(
                serde_urlencoded::to_string(json!({
                    "client_id": "confidential",
                    "client_secret": CLIENT_SECRET,
                    "foo": "baz",
                    "bar": "foobar",
                }))
                .unwrap(),
            )
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthenticationMethod::ClientSecretPost);
        assert_eq!(client.client_id, "confidential");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn client_secret_basic() {
        let filter = client_authentication::<Form>(
            &oauth2_config(),
            "https://example.com/token".to_string(),
        );

        let auth = Authorization::basic("confidential", CLIENT_SECRET);
        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header(
                "Content-Type",
                mime::APPLICATION_WWW_FORM_URLENCODED.to_string(),
            )
            .header("Authorization", auth.0.encode())
            .body(
                serde_urlencoded::to_string(json!({
                    "foo": "baz",
                    "bar": "foobar",
                }))
                .unwrap(),
            )
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthenticationMethod::ClientSecretBasic);
        assert_eq!(client.client_id, "confidential");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn none() {
        let filter = client_authentication::<Form>(
            &oauth2_config(),
            "https://example.com/token".to_string(),
        );

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header(
                "Content-Type",
                mime::APPLICATION_WWW_FORM_URLENCODED.to_string(),
            )
            .body(
                serde_urlencoded::to_string(json!({
                    "client_id": "public",
                    "foo": "baz",
                    "bar": "foobar",
                }))
                .unwrap(),
            )
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, ClientAuthenticationMethod::None);
        assert_eq!(client.client_id, "public");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }
}
