// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::collections::HashMap;

use async_trait::async_trait;
use axum::{
    body::HttpBody,
    extract::{
        rejection::{FailedToDeserializeQueryString, FormRejection, TypedHeaderRejectionReason},
        Form, FromRequest, RequestParts, TypedHeader,
    },
    response::IntoResponse,
    BoxError,
};
use headers::{authorization::Basic, Authorization};
use http::StatusCode;
use mas_config::Encrypter;
use mas_data_model::{Client, JwksOrJwksUri, StorageBackend};
use mas_http::HttpServiceExt;
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_jose::{
    DecodedJsonWebToken, DynamicJwksStore, Either, JsonWebKeySet, JsonWebTokenParts, JwtHeader,
    SharedSecret, StaticJwksStore, VerifyingKeystore,
};
use mas_storage::{
    oauth2::client::{lookup_client_by_client_id, ClientFetchError},
    PostgresqlBackend,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use sqlx::PgExecutor;
use thiserror::Error;
use tower::ServiceExt;

static JWT_BEARER_CLIENT_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Deserialize)]
struct AuthorizedForm<F = ()> {
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Credentials {
    None {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: String,
    },
    ClientAssertionJwtBearer {
        client_id: String,
        jwt: JsonWebTokenParts,
        header: Box<JwtHeader>,
        claims: HashMap<String, Value>,
    },
}

impl Credentials {
    pub async fn fetch(
        &self,
        executor: impl PgExecutor<'_>,
    ) -> Result<Client<PostgresqlBackend>, ClientFetchError> {
        let client_id = match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => client_id,
        };

        lookup_client_by_client_id(executor, client_id).await
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn verify<S: StorageBackend>(
        &self,
        encrypter: &Encrypter,
        method: OAuthClientAuthenticationMethod,
        client: &Client<S>,
    ) -> Result<(), CredentialsVerificationError> {
        match (self, method) {
            (Credentials::None { .. }, OAuthClientAuthenticationMethod::None) => {}

            (
                Credentials::ClientSecretPost { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretPost,
            )
            | (
                Credentials::ClientSecretBasic { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretBasic,
            ) => {
                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                // Check if the client_secret matches
                if client_secret.as_bytes() != decrypted_client_secret {
                    return Err(CredentialsVerificationError::ClientSecretMismatch);
                }
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, header, .. },
                OAuthClientAuthenticationMethod::PrivateKeyJwt,
            ) => {
                // Get the client JWKS
                let jwks = client
                    .jwks
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let store: Either<StaticJwksStore, DynamicJwksStore> = jwks_key_store(jwks);
                let fut = jwt.verify(header, &store);
                fut.await
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, header, .. },
                OAuthClientAuthenticationMethod::ClientSecretJwt,
            ) => {
                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                let store = SharedSecret::new(&decrypted_client_secret);
                let fut = jwt.verify(header, &store);
                fut.await
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (_, _) => {
                return Err(CredentialsVerificationError::AuthenticationMethodMismatch);
            }
        };
        Ok(())
    }
}

fn jwks_key_store(jwks: &JwksOrJwksUri) -> Either<StaticJwksStore, DynamicJwksStore> {
    // Assert that the output is both a VerifyingKeystore and Send
    fn assert<T: Send + VerifyingKeystore>(t: T) -> T {
        t
    }

    let inner = match jwks {
        JwksOrJwksUri::Jwks(jwks) => Either::Left(StaticJwksStore::new(jwks.clone())),
        JwksOrJwksUri::JwksUri(uri) => {
            let uri = uri.clone();

            // TODO: get the client from somewhere else?
            let exporter = mas_http::client("fetch-jwks")
                .json::<JsonWebKeySet>()
                .map_request(move |_: ()| {
                    http::Request::builder()
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

#[derive(Debug, Error)]
pub enum CredentialsVerificationError {
    #[error("failed to decrypt client credentials")]
    DecryptionError,

    #[error("invalid client configuration")]
    InvalidClientConfig,

    #[error("client secret did not match")]
    ClientSecretMismatch,

    #[error("authentication method mismatch")]
    AuthenticationMethodMismatch,

    #[error("invalid assertion signature")]
    InvalidAssertionSignature,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientAuthorization<F = ()> {
    pub credentials: Credentials,
    pub form: Option<F>,
}

#[derive(Debug)]
pub enum ClientAuthorizationError {
    InvalidHeader,
    BadForm(FailedToDeserializeQueryString),
    ClientIdMismatch { credential: String, form: String },
    UnsupportedClientAssertion { client_assertion_type: String },
    MissingCredentials,
    InvalidRequest,
    InvalidAssertion,
    InternalError(Box<dyn std::error::Error>),
}

impl IntoResponse for ClientAuthorizationError {
    fn into_response(self) -> axum::response::Response {
        // TODO
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[async_trait]
impl<B, F> FromRequest<B> for ClientAuthorization<F>
where
    B: Send + HttpBody,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
    F: DeserializeOwned,
{
    type Rejection = ClientAuthorizationError;

    #[allow(clippy::too_many_lines)]
    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let header = TypedHeader::<Authorization<Basic>>::from_request(req).await;

        // Take the Authorization header
        let credentials_from_header = match header {
            Ok(header) => Some((header.username().to_owned(), header.password().to_owned())),
            Err(err) => match err.reason() {
                // If it's missing it is fine
                TypedHeaderRejectionReason::Missing => None,
                // If the header could not be parsed, return the error
                _ => return Err(ClientAuthorizationError::InvalidHeader),
            },
        };

        // Take the form value
        let (
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
            form,
        ) = match Form::<AuthorizedForm<F>>::from_request(req).await {
            Ok(Form(form)) => (
                form.client_id,
                form.client_secret,
                form.client_assertion_type,
                form.client_assertion,
                Some(form.inner),
            ),
            // If it is not a form, continue
            Err(FormRejection::InvalidFormContentType(_err)) => (None, None, None, None, None),
            // If the form could not be read, return a Bad Request error
            Err(FormRejection::FailedToDeserializeQueryString(err)) => {
                return Err(ClientAuthorizationError::BadForm(err))
            }
            // Other errors (body read twice, byte stream broke) return an internal error
            Err(e) => return Err(ClientAuthorizationError::InternalError(Box::new(e))),
        };

        // And now, figure out the actual auth method
        let credentials = match (
            credentials_from_header,
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
        ) {
            (Some((client_id, client_secret)), client_id_from_form, None, None, None) => {
                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches with the header
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientSecretBasic {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), Some(client_secret), None, None) => {
                // Got both client_id and client_secret from the form
                Credentials::ClientSecretPost {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), None, None, None) => {
                // Only got a client_id in the form
                Credentials::None { client_id }
            }

            (
                None,
                client_id_from_form,
                None,
                Some(client_assertion_type),
                Some(client_assertion),
            ) if client_assertion_type == JWT_BEARER_CLIENT_ASSERTION => {
                // Got a JWT bearer client_assertion

                let jwt: JsonWebTokenParts = client_assertion
                    .parse()
                    .map_err(|_| ClientAuthorizationError::InvalidAssertion)?;
                let decoded: DecodedJsonWebToken<HashMap<String, Value>> = jwt
                    .decode()
                    .map_err(|_| ClientAuthorizationError::InvalidAssertion)?;
                let (header, claims) = decoded.split();

                let client_id = if let Some(Value::String(client_id)) = claims.get("sub") {
                    client_id.clone()
                } else {
                    return Err(ClientAuthorizationError::InvalidAssertion);
                };

                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches the one in the JWT
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientAssertionJwtBearer {
                    client_id,
                    jwt,
                    header: Box::new(header),
                    claims,
                }
            }

            (None, None, None, Some(client_assertion_type), Some(_client_assertion)) => {
                // Got another unsupported client_assertion
                return Err(ClientAuthorizationError::UnsupportedClientAssertion {
                    client_assertion_type,
                });
            }

            (None, None, None, None, None) => {
                // Special case when there are no credentials anywhere
                return Err(ClientAuthorizationError::MissingCredentials);
            }

            _ => {
                // Every other combination is an invalid request
                return Err(ClientAuthorizationError::InvalidRequest);
            }
        };

        Ok(ClientAuthorization { credentials, form })
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Bytes, Full};
    use http::{Method, Request};

    use super::*;

    #[tokio::test]
    async fn none_test() {
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .body(Full::<Bytes>::new("client_id=client-id&foo=bar".into()))
                .unwrap(),
        );

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req)
                .await
                .unwrap(),
            ClientAuthorization {
                credentials: Credentials::None {
                    client_id: "client-id".to_owned(),
                },
                form: Some(serde_json::json!({"foo": "bar"})),
            }
        );
    }

    #[tokio::test]
    async fn client_secret_basic_test() {
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .header(
                    http::header::AUTHORIZATION,
                    "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=",
                )
                .body(Full::<Bytes>::new("foo=bar".into()))
                .unwrap(),
        );

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req)
                .await
                .unwrap(),
            ClientAuthorization {
                credentials: Credentials::ClientSecretBasic {
                    client_id: "client-id".to_owned(),
                    client_secret: "client-secret".to_owned(),
                },
                form: Some(serde_json::json!({"foo": "bar"})),
            }
        );

        // client_id in both header and body
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .header(
                    http::header::AUTHORIZATION,
                    "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=",
                )
                .body(Full::<Bytes>::new("client_id=client-id&foo=bar".into()))
                .unwrap(),
        );

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req)
                .await
                .unwrap(),
            ClientAuthorization {
                credentials: Credentials::ClientSecretBasic {
                    client_id: "client-id".to_owned(),
                    client_secret: "client-secret".to_owned(),
                },
                form: Some(serde_json::json!({"foo": "bar"})),
            }
        );

        // client_id in both header and body mismatch
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .header(
                    http::header::AUTHORIZATION,
                    "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=",
                )
                .body(Full::<Bytes>::new("client_id=mismatch-id&foo=bar".into()))
                .unwrap(),
        );

        assert!(matches!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req).await,
            Err(ClientAuthorizationError::ClientIdMismatch { .. }),
        ));

        // Invalid header
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .header(http::header::AUTHORIZATION, "Basic invalid")
                .body(Full::<Bytes>::new("foo=bar".into()))
                .unwrap(),
        );

        assert!(matches!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req).await,
            Err(ClientAuthorizationError::InvalidHeader),
        ));
    }

    #[tokio::test]
    async fn client_secret_post_test() {
        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .body(Full::<Bytes>::new(
                    "client_id=client-id&client_secret=client-secret&foo=bar".into(),
                ))
                .unwrap(),
        );

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(&mut req)
                .await
                .unwrap(),
            ClientAuthorization {
                credentials: Credentials::ClientSecretPost {
                    client_id: "client-id".to_owned(),
                    client_secret: "client-secret".to_owned(),
                },
                form: Some(serde_json::json!({"foo": "bar"})),
            }
        );
    }

    #[tokio::test]
    async fn client_assertion_test() {
        // Signed with client_secret = "client-secret"
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjbGllbnQtaWQiLCJzdWIiOiJjbGllbnQtaWQiLCJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL29hdXRoMi9pbnRyb3NwZWN0IiwianRpIjoiYWFiYmNjIiwiZXhwIjoxNTE2MjM5MzIyLCJpYXQiOjE1MTYyMzkwMjJ9.XTaACG_Rww0GPecSZvkbem-AczNy9LLNBueCLCiQajU";
        let body = Bytes::from(format!(
            "client_assertion_type={}&client_assertion={}&foo=bar",
            JWT_BEARER_CLIENT_ASSERTION, jwt,
        ));

        let mut req = RequestParts::new(
            Request::builder()
                .method(Method::POST)
                .header(
                    http::header::CONTENT_TYPE,
                    mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
                )
                .body(Full::new(body))
                .unwrap(),
        );

        let authz = ClientAuthorization::<serde_json::Value>::from_request(&mut req)
            .await
            .unwrap();
        assert_eq!(authz.form, Some(serde_json::json!({"foo": "bar"})));

        let (client_id, _jwt, _header, _claims) = if let Credentials::ClientAssertionJwtBearer {
            client_id,
            jwt,
            header,
            claims,
        } = authz.credentials
        {
            (client_id, jwt, header, claims)
        } else {
            panic!("expected a JWT client_assertion");
        };

        assert_eq!(client_id, "client-id");
        // TODO: test more things
    }
}
