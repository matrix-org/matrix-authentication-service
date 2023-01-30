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
        rejection::{FailedToDeserializeForm, FormRejection, TypedHeaderRejectionReason},
        Form, FromRequest, FromRequestParts, TypedHeader,
    },
    response::IntoResponse,
    BoxError,
};
use headers::{authorization::Basic, Authorization};
use http::{Request, StatusCode};
use mas_data_model::{Client, JwksOrJwksUri};
use mas_http::HttpServiceExt;
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_jose::{jwk::PublicJsonWebKeySet, jwt::Jwt};
use mas_keystore::Encrypter;
use mas_storage::{oauth2::OAuth2ClientRepository, RepositoryAccess};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use thiserror::Error;
use tower::{Service, ServiceExt};

use crate::http_client_factory::HttpClientFactory;

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
        jwt: Box<Jwt<'static, HashMap<String, serde_json::Value>>>,
    },
}

impl Credentials {
    /// Get the `client_id` of the credentials
    #[must_use]
    pub fn client_id(&self) -> &str {
        match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => client_id,
        }
    }

    pub async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<Client>, E> {
        let client_id = match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => client_id,
        };

        repo.oauth2_client().find_by_client_id(client_id).await
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn verify(
        &self,
        http_client_factory: &HttpClientFactory,
        encrypter: &Encrypter,
        method: &OAuthClientAuthenticationMethod,
        client: &Client,
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
                Credentials::ClientAssertionJwtBearer { jwt, .. },
                OAuthClientAuthenticationMethod::PrivateKeyJwt,
            ) => {
                // Get the client JWKS
                let jwks = client
                    .jwks
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let jwks = fetch_jwks(http_client_factory, jwks)
                    .await
                    .map_err(|_| CredentialsVerificationError::JwksFetchFailed)?;

                jwt.verify_with_jwks(&jwks)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, .. },
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

                jwt.verify_with_shared_secret(decrypted_client_secret)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
            }

            (_, _) => {
                return Err(CredentialsVerificationError::AuthenticationMethodMismatch);
            }
        };
        Ok(())
    }
}

async fn fetch_jwks(
    http_client_factory: &HttpClientFactory,
    jwks: &JwksOrJwksUri,
) -> Result<PublicJsonWebKeySet, BoxError> {
    let uri = match jwks {
        JwksOrJwksUri::Jwks(j) => return Ok(j.clone()),
        JwksOrJwksUri::JwksUri(u) => u,
    };

    let request = http::Request::builder()
        .uri(uri.as_str())
        .body(mas_http::EmptyBody::new())
        .unwrap();

    let mut client = http_client_factory
        .client("fetch-jwks")
        .await?
        .response_body_to_bytes()
        .json_response::<PublicJsonWebKeySet>();

    let response = client.ready().await?.call(request).await?;

    Ok(response.into_body())
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

    #[error("failed to fetch jwks")]
    JwksFetchFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientAuthorization<F = ()> {
    pub credentials: Credentials,
    pub form: Option<F>,
}

impl<F> ClientAuthorization<F> {
    /// Get the `client_id` from the credentials.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.credentials.client_id()
    }
}

#[derive(Debug)]
pub enum ClientAuthorizationError {
    InvalidHeader,
    BadForm(FailedToDeserializeForm),
    ClientIdMismatch { credential: String, form: String },
    UnsupportedClientAssertion { client_assertion_type: String },
    MissingCredentials,
    InvalidRequest,
    InvalidAssertion,
    Internal(Box<dyn std::error::Error>),
}

impl IntoResponse for ClientAuthorizationError {
    fn into_response(self) -> axum::response::Response {
        // TODO
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[async_trait]
impl<S, B, F> FromRequest<S, B> for ClientAuthorization<F>
where
    F: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = ClientAuthorizationError;

    #[allow(clippy::too_many_lines)]
    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        // Split the request into parts so we can extract some headers
        let (mut parts, body) = req.into_parts();

        let header =
            TypedHeader::<Authorization<Basic>>::from_request_parts(&mut parts, state).await;

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

        // Reconstruct the request from the parts
        let req = Request::from_parts(parts, body);

        // Take the form value
        let (
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
            form,
        ) = match Form::<AuthorizedForm<F>>::from_request(req, state).await {
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
            Err(FormRejection::FailedToDeserializeForm(err)) => {
                return Err(ClientAuthorizationError::BadForm(err))
            }
            // Other errors (body read twice, byte stream broke) return an internal error
            Err(e) => return Err(ClientAuthorizationError::Internal(Box::new(e))),
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
                let jwt: Jwt<'static, HashMap<String, Value>> = Jwt::try_from(client_assertion)
                    .map_err(|_| ClientAuthorizationError::InvalidAssertion)?;

                let client_id = if let Some(Value::String(client_id)) = jwt.payload().get("sub") {
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
                    jwt: Box::new(jwt),
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
        let req = Request::builder()
            .method(Method::POST)
            .header(
                http::header::CONTENT_TYPE,
                mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
            )
            .body(Full::<Bytes>::new("client_id=client-id&foo=bar".into()))
            .unwrap();

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &())
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
        let req = Request::builder()
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
            .unwrap();

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &())
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
        let req = Request::builder()
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
            .unwrap();

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &())
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
        let req = Request::builder()
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
            .unwrap();

        assert!(matches!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &()).await,
            Err(ClientAuthorizationError::ClientIdMismatch { .. }),
        ));

        // Invalid header
        let req = Request::builder()
            .method(Method::POST)
            .header(
                http::header::CONTENT_TYPE,
                mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
            )
            .header(http::header::AUTHORIZATION, "Basic invalid")
            .body(Full::<Bytes>::new("foo=bar".into()))
            .unwrap();

        assert!(matches!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &()).await,
            Err(ClientAuthorizationError::InvalidHeader),
        ));
    }

    #[tokio::test]
    async fn client_secret_post_test() {
        let req = Request::builder()
            .method(Method::POST)
            .header(
                http::header::CONTENT_TYPE,
                mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
            )
            .body(Full::<Bytes>::new(
                "client_id=client-id&client_secret=client-secret&foo=bar".into(),
            ))
            .unwrap();

        assert_eq!(
            ClientAuthorization::<serde_json::Value>::from_request(req, &())
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

        let req = Request::builder()
            .method(Method::POST)
            .header(
                http::header::CONTENT_TYPE,
                mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
            )
            .body(Full::new(body))
            .unwrap();

        let authz = ClientAuthorization::<serde_json::Value>::from_request(req, &())
            .await
            .unwrap();
        assert_eq!(authz.form, Some(serde_json::json!({"foo": "bar"})));

        let (client_id, jwt) =
            if let Credentials::ClientAssertionJwtBearer { client_id, jwt } = authz.credentials {
                (client_id, jwt)
            } else {
                panic!("expected a JWT client_assertion");
            };

        assert_eq!(client_id, "client-id");
        jwt.verify_with_shared_secret(b"client-secret".to_vec())
            .unwrap();
    }
}
