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

use std::collections::HashMap;

use headers::{authorization::Basic, Authorization};
use mas_config::{ClientAuthMethodConfig, ClientConfig, ClientsConfig};
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_jose::{
    claims::{TimeOptions, AUD, EXP, IAT, ISS, JTI, NBF, SUB},
    DecodedJsonWebToken, JsonWebTokenParts, SharedSecret,
};
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection};

use super::headers::typed_header;
use crate::errors::WrapError;

/// Protect an enpoint with client authentication
#[must_use]
pub fn client_authentication<T: DeserializeOwned + Send + 'static>(
    clients_config: &ClientsConfig,
    audience: String,
) -> impl Filter<Extract = (OAuthClientAuthenticationMethod, ClientConfig, T), Error = Rejection>
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

    let clients_config = clients_config.clone();
    warp::any()
        .map(move || clients_config.clone())
        .and(warp::any().map(move || audience.clone()))
        .and(credentials)
        .and_then(authenticate_client)
        .untuple_one()
}

#[derive(Error, Debug)]
enum ClientAuthenticationError {
    #[error("wrong client secret for client {client_id:?}")]
    ClientSecretMismatch { client_id: String },

    #[error("could not find client {client_id:?}")]
    ClientNotFound { client_id: String },

    #[error("wrong client authentication method for client {client_id:?}")]
    WrongAuthenticationMethod { client_id: String },

    #[error("wrong audience in client assertion: expected {expected:?}")]
    MissingAudience { expected: String },

    #[error("invalid client assertion")]
    InvalidAssertion,
}

impl Reject for ClientAuthenticationError {}

#[allow(clippy::too_many_lines)]
#[tracing::instrument(skip_all, fields(enduser.id), err(Debug))]
async fn authenticate_client<T>(
    clients_config: ClientsConfig,
    audience: String,
    credentials: ClientCredentials,
    body: T,
) -> Result<(OAuthClientAuthenticationMethod, ClientConfig, T), Rejection> {
    let (auth_method, client) = match credentials {
        ClientCredentials::Pair {
            client_id,
            client_secret,
            via,
        } => {
            let client = clients_config
                .iter()
                .find(|client| client.client_id == client_id)
                .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
                    client_id: client_id.to_string(),
                })?;

            let auth_method = match (&client.client_auth_method, client_secret, via) {
                (ClientAuthMethodConfig::None, None, _) => OAuthClientAuthenticationMethod::None,

                (
                    ClientAuthMethodConfig::ClientSecretBasic {
                        client_secret: ref expected_client_secret,
                    },
                    Some(ref given_client_secret),
                    CredentialsVia::AuthorizationHeader,
                ) => {
                    if expected_client_secret != given_client_secret {
                        return Err(
                            ClientAuthenticationError::ClientSecretMismatch { client_id }.into(),
                        );
                    }

                    OAuthClientAuthenticationMethod::ClientSecretBasic
                }

                (
                    ClientAuthMethodConfig::ClientSecretPost {
                        client_secret: ref expected_client_secret,
                    },
                    Some(ref given_client_secret),
                    CredentialsVia::FormBody,
                ) => {
                    if expected_client_secret != given_client_secret {
                        return Err(
                            ClientAuthenticationError::ClientSecretMismatch { client_id }.into(),
                        );
                    }

                    OAuthClientAuthenticationMethod::ClientSecretPost
                }

                _ => {
                    return Err(
                        ClientAuthenticationError::WrongAuthenticationMethod { client_id }.into(),
                    )
                }
            };

            (auth_method, client)
        }
        ClientCredentials::Assertion {
            client_id,
            client_assertion_type: ClientAssertionType::JwtBearer,
            client_assertion,
        } => {
            let token: JsonWebTokenParts = client_assertion.parse().wrap_error()?;
            let decoded: DecodedJsonWebToken<HashMap<String, serde_json::Value>> =
                token.decode().wrap_error()?;

            let time_options = TimeOptions::default()
                .freeze()
                .leeway(chrono::Duration::minutes(1));

            let mut claims = decoded.claims().clone();
            let iss = ISS.extract_required(&mut claims).wrap_error()?;
            let sub = SUB.extract_required(&mut claims).wrap_error()?;
            let aud = AUD.extract_required(&mut claims).wrap_error()?;

            // Validate the times
            let _exp = EXP
                .extract_required_with_options(&mut claims, &time_options)
                .wrap_error()?;
            let _nbf = NBF
                .extract_optional_with_options(&mut claims, &time_options)
                .wrap_error()?;
            let _iat = IAT
                .extract_optional_with_options(&mut claims, &time_options)
                .wrap_error()?;

            // TODO: validate the JTI
            let _jti = JTI.extract_optional(&mut claims).wrap_error()?;

            // client_id might have been passed as parameter. If not, it should be inferred
            // from the token, as per rfc7521 sec. 4.2
            let client_id = client_id.as_ref().unwrap_or(&sub);

            let client = clients_config
                .iter()
                .find(|client| &client.client_id == client_id)
                .ok_or_else(|| ClientAuthenticationError::ClientNotFound {
                    client_id: client_id.to_string(),
                })?;

            let auth_method = match &client.client_auth_method {
                ClientAuthMethodConfig::PrivateKeyJwt(jwks) => {
                    let store = jwks.key_store();
                    let fut = token.verify(&decoded, &store);
                    fut.await.wrap_error()?;
                    OAuthClientAuthenticationMethod::PrivateKeyJwt
                }

                ClientAuthMethodConfig::ClientSecretJwt { client_secret } => {
                    let store = SharedSecret::new(client_secret);
                    token.verify(&decoded, &store).await.wrap_error()?;
                    OAuthClientAuthenticationMethod::ClientSecretJwt
                }

                _ => {
                    return Err(ClientAuthenticationError::WrongAuthenticationMethod {
                        client_id: client_id.clone(),
                    }
                    .into())
                }
            };

            // rfc7523 sec. 3.3: the audience is the URL being called
            if !aud.contains(&audience) {
                return Err(
                    ClientAuthenticationError::MissingAudience { expected: audience }.into(),
                );
            }

            // rfc7523 sec. 3.1 & 3.2: both the issuer and the subject must
            // match the client_id
            if iss != sub || &iss != client_id {
                return Err(ClientAuthenticationError::InvalidAssertion.into());
            }

            (auth_method, client)
        }
    };

    tracing::Span::current().record("enduser.id", &client.client_id.as_str());

    Ok((auth_method, client.clone(), body))
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
    use mas_config::{ClientAuthMethodConfig, ConfigurationSection};
    use mas_jose::{SigningKeystore, StaticKeystore};
    use serde_json::json;
    use tower::{Service, ServiceExt};

    use super::*;

    // Long client_secret to support it as a HS512 key
    const CLIENT_SECRET: &str = "leek2zaeyeb8thai7piehea3vah6ool9oanin9aeraThuci9EeghaekaiD1upe4Quoh7xeMae2meitohj0Waaveiwaorah1yazohr6Vae7iebeiRaWene5IeWeeciezu";

    fn client_private_keystore() -> StaticKeystore {
        let mut store = StaticKeystore::new();
        store.add_test_rsa_key().unwrap();
        store.add_test_ecdsa_key().unwrap();
        store
    }

    async fn oauth2_config() -> ClientsConfig {
        let mut config = ClientsConfig::test();
        config.push(ClientConfig {
            client_id: "public".to_string(),
            client_auth_method: ClientAuthMethodConfig::None,
            redirect_uris: Vec::new(),
        });
        config.push(ClientConfig {
            client_id: "secret-basic".to_string(),
            client_auth_method: ClientAuthMethodConfig::ClientSecretBasic {
                client_secret: CLIENT_SECRET.to_string(),
            },
            redirect_uris: Vec::new(),
        });
        config.push(ClientConfig {
            client_id: "secret-post".to_string(),
            client_auth_method: ClientAuthMethodConfig::ClientSecretPost {
                client_secret: CLIENT_SECRET.to_string(),
            },
            redirect_uris: Vec::new(),
        });
        config.push(ClientConfig {
            client_id: "secret-jwt".to_string(),
            client_auth_method: ClientAuthMethodConfig::ClientSecretJwt {
                client_secret: CLIENT_SECRET.to_string(),
            },
            redirect_uris: Vec::new(),
        });
        config.push(ClientConfig {
            client_id: "secret-jwt-2".to_string(),
            client_auth_method: ClientAuthMethodConfig::ClientSecretJwt {
                client_secret: CLIENT_SECRET.to_string(),
            },
            redirect_uris: Vec::new(),
        });

        let store = client_private_keystore();
        let jwks = (&store).ready().await.unwrap().call(()).await.unwrap();
        //let jwks = store.export_jwks().await.unwrap();
        config.push(ClientConfig {
            client_id: "private-key-jwt".to_string(),
            client_auth_method: ClientAuthMethodConfig::PrivateKeyJwt(jwks.clone().into()),
            redirect_uris: Vec::new(),
        });
        config.push(ClientConfig {
            client_id: "private-key-jwt-2".to_string(),
            client_auth_method: ClientAuthMethodConfig::PrivateKeyJwt(jwks.into()),
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
        client_secret_jwt("HS256").await;
    }

    #[tokio::test]
    async fn client_secret_jwt_hs384() {
        client_secret_jwt("HS384").await;
    }

    #[tokio::test]
    async fn client_secret_jwt_hs512() {
        client_secret_jwt("HS512").await;
    }

    fn client_claims(
        client_id: &str,
        audience: &str,
        iat: chrono::DateTime<chrono::Utc>,
    ) -> HashMap<String, serde_json::Value> {
        let mut claims = HashMap::new();
        let exp = iat + chrono::Duration::minutes(1);

        ISS.insert(&mut claims, client_id).unwrap();
        SUB.insert(&mut claims, client_id).unwrap();
        AUD.insert(&mut claims, vec![audience.to_string()]).unwrap();
        IAT.insert(&mut claims, iat).unwrap();
        NBF.insert(&mut claims, iat).unwrap();
        EXP.insert(&mut claims, exp).unwrap();

        claims
    }

    async fn client_secret_jwt(alg: &str) {
        let alg = alg.parse().unwrap();
        let audience = "https://example.com/token";
        let filter = client_authentication::<Form>(&oauth2_config().await, audience.to_string());

        let store = SharedSecret::new(&CLIENT_SECRET);
        let claims = client_claims("secret-jwt", audience, chrono::Utc::now());
        let header = store.prepare_header(alg).await.expect("JWT header");
        let jwt = DecodedJsonWebToken::new(header, claims);
        let jwt = jwt.sign(&store).await.expect("signed token");
        let jwt = jwt.serialize();

        // TODO: test failing cases
        //  - expired token
        //  - "not before" in the future
        //  - subject/issuer mismatch
        //  - audience mismatch
        //  - wrong secret/signature

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_id": "secret-jwt",
                "client_assertion": jwt,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, OAuthClientAuthenticationMethod::ClientSecretJwt);
        assert_eq!(client.client_id, "secret-jwt");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");

        // Without client_id
        let res = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_assertion": jwt,
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
                "client_id": "secret-jwt-2",
                "client_assertion": jwt,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn client_secret_jwt_rs256() {
        private_key_jwt("RS256").await;
    }

    #[tokio::test]
    async fn client_secret_jwt_rs384() {
        private_key_jwt("RS384").await;
    }

    #[tokio::test]
    async fn client_secret_jwt_rs512() {
        private_key_jwt("RS512").await;
    }

    #[tokio::test]
    async fn client_secret_jwt_es256() {
        private_key_jwt("ES256").await;
    }

    async fn private_key_jwt(alg: &str) {
        let alg = alg.parse().unwrap();
        let audience = "https://example.com/token";
        let filter = client_authentication::<Form>(&oauth2_config().await, audience.to_string());

        let store = client_private_keystore();
        let claims = client_claims("private-key-jwt", audience, chrono::Utc::now());
        let header = store.prepare_header(alg).await.expect("JWT header");
        let jwt = DecodedJsonWebToken::new(header, claims);
        let jwt = jwt.sign(&store).await.expect("signed token");
        let jwt = jwt.serialize();

        // TODO: test failing cases
        //  - expired token
        //  - "not before" in the future
        //  - subject/issuer mismatch
        //  - audience mismatch
        //  - wrong secret/signature

        let (auth, client, body) = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_id": "private-key-jwt",
                "client_assertion": jwt,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "foo": "baz",
                "bar": "foobar",
            })).unwrap())
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, OAuthClientAuthenticationMethod::PrivateKeyJwt);
        assert_eq!(client.client_id, "private-key-jwt");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");

        // Without client_id
        let res = warp::test::request()
            .method("POST")
            .header("Content-Type", mime::APPLICATION_WWW_FORM_URLENCODED.to_string())
            .body(serde_urlencoded::to_string(json!({
                "client_assertion": jwt,
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
                "client_id": "private-key-jwt-2",
                "client_assertion": jwt,
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
            &oauth2_config().await,
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
                    "client_id": "secret-post",
                    "client_secret": CLIENT_SECRET,
                    "foo": "baz",
                    "bar": "foobar",
                }))
                .unwrap(),
            )
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(auth, OAuthClientAuthenticationMethod::ClientSecretPost);
        assert_eq!(client.client_id, "secret-post");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn client_secret_basic() {
        let filter = client_authentication::<Form>(
            &oauth2_config().await,
            "https://example.com/token".to_string(),
        );

        let auth = Authorization::basic("secret-basic", CLIENT_SECRET);
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

        assert_eq!(auth, OAuthClientAuthenticationMethod::ClientSecretBasic);
        assert_eq!(client.client_id, "secret-basic");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }

    #[tokio::test]
    async fn none() {
        let filter = client_authentication::<Form>(
            &oauth2_config().await,
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

        assert_eq!(auth, OAuthClientAuthenticationMethod::None);
        assert_eq!(client.client_id, "public");
        assert_eq!(body.foo, "baz");
        assert_eq!(body.bar, "foobar");
    }
}
