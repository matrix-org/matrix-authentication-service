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

use std::{collections::HashMap, error::Error};

use async_trait::async_trait;
use axum::{
    body::HttpBody,
    extract::{
        rejection::{FailedToDeserializeForm, FormRejection, TypedHeaderRejectionReason},
        Form, FromRequest, FromRequestParts, TypedHeader,
    },
    response::{IntoResponse, Response},
    BoxError,
};
use headers::{authorization::Bearer, Authorization, Header, HeaderMapExt, HeaderName};
use http::{header::WWW_AUTHENTICATE, HeaderMap, HeaderValue, Request, StatusCode};
use mas_data_model::Session;
use mas_storage::{
    oauth2::{OAuth2AccessTokenRepository, OAuth2SessionRepository},
    Clock, RepositoryAccess,
};
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct AuthorizedForm<F> {
    #[serde(default)]
    access_token: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug)]
enum AccessToken {
    Form(String),
    Header(String),
    None,
}

impl AccessToken {
    async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<(mas_data_model::AccessToken, Session), AuthorizationVerificationError<E>> {
        let token = match self {
            AccessToken::Form(t) | AccessToken::Header(t) => t,
            AccessToken::None => return Err(AuthorizationVerificationError::MissingToken),
        };

        let token = repo
            .oauth2_access_token()
            .find_by_token(token.as_str())
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        let session = repo
            .oauth2_session()
            .lookup(token.session_id)
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        Ok((token, session))
    }
}

#[derive(Debug)]
pub struct UserAuthorization<F = ()> {
    access_token: AccessToken,
    form: Option<F>,
}

impl<F: Send> UserAuthorization<F> {
    // TODO: take scopes to validate as parameter
    pub async fn protected_form<E>(
        self,
        repo: &mut impl RepositoryAccess<Error = E>,
        clock: &impl Clock,
    ) -> Result<(Session, F), AuthorizationVerificationError<E>> {
        let Some(form) = self.form else {
            return Err(AuthorizationVerificationError::MissingForm);
        };

        let (token, session) = self.access_token.fetch(repo).await?;

        if !token.is_valid(clock.now()) || !session.is_valid() {
            return Err(AuthorizationVerificationError::InvalidToken);
        }

        Ok((session, form))
    }

    // TODO: take scopes to validate as parameter
    pub async fn protected<E>(
        self,
        repo: &mut impl RepositoryAccess<Error = E>,
        clock: &impl Clock,
    ) -> Result<Session, AuthorizationVerificationError<E>> {
        let (token, session) = self.access_token.fetch(repo).await?;

        if !token.is_valid(clock.now()) || !session.is_valid() {
            return Err(AuthorizationVerificationError::InvalidToken);
        }

        Ok(session)
    }
}

pub enum UserAuthorizationError {
    InvalidHeader,
    TokenInFormAndHeader,
    BadForm(FailedToDeserializeForm),
    Internal(Box<dyn Error>),
}

#[derive(Debug, Error)]
pub enum AuthorizationVerificationError<E> {
    #[error("missing token")]
    MissingToken,

    #[error("invalid token")]
    InvalidToken,

    #[error("missing form")]
    MissingForm,

    #[error(transparent)]
    Internal(#[from] E),
}

enum BearerError {
    InvalidRequest,
    InvalidToken,
    #[allow(dead_code)]
    InsufficientScope {
        scope: Option<HeaderValue>,
    },
}

impl BearerError {
    fn error(&self) -> HeaderValue {
        match self {
            BearerError::InvalidRequest => HeaderValue::from_static("invalid_request"),
            BearerError::InvalidToken => HeaderValue::from_static("invalid_token"),
            BearerError::InsufficientScope { .. } => HeaderValue::from_static("insufficient_scope"),
        }
    }

    fn params(&self) -> HashMap<&'static str, HeaderValue> {
        match self {
            BearerError::InsufficientScope { scope: Some(scope) } => {
                let mut m = HashMap::new();
                m.insert("scope", scope.clone());
                m
            }
            _ => HashMap::new(),
        }
    }
}

enum WwwAuthenticate {
    #[allow(dead_code)]
    Basic { realm: HeaderValue },
    Bearer {
        realm: Option<HeaderValue>,
        error: BearerError,
        error_description: Option<HeaderValue>,
    },
}

impl Header for WwwAuthenticate {
    fn name() -> &'static HeaderName {
        &WWW_AUTHENTICATE
    }

    fn decode<'i, I>(_values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        Err(headers::Error::invalid())
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        let (scheme, params) = match self {
            WwwAuthenticate::Basic { realm } => {
                let mut params = HashMap::new();
                params.insert("realm", realm.clone());
                ("Basic", params)
            }
            WwwAuthenticate::Bearer {
                realm,
                error,
                error_description,
            } => {
                let mut params = error.params();
                params.insert("error", error.error());

                if let Some(realm) = realm {
                    params.insert("realm", realm.clone());
                }

                if let Some(error_description) = error_description {
                    params.insert("error_description", error_description.clone());
                }

                ("Bearer", params)
            }
        };

        let params = params.into_iter().map(|(k, v)| format!(" {k}={v:?}"));
        let value: String = std::iter::once(scheme.to_owned()).chain(params).collect();
        let value = HeaderValue::from_str(&value).unwrap();
        values.extend(std::iter::once(value));
    }
}

impl IntoResponse for UserAuthorizationError {
    fn into_response(self) -> Response {
        match self {
            Self::BadForm(_) | Self::InvalidHeader | Self::TokenInFormAndHeader => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

impl<E> IntoResponse for AuthorizationVerificationError<E>
where
    E: ToString,
{
    fn into_response(self) -> Response {
        match self {
            Self::MissingForm | Self::MissingToken => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::InvalidToken => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidToken,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

#[async_trait]
impl<S, B, F> FromRequest<S, B> for UserAuthorization<F>
where
    F: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = UserAuthorizationError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let header =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(&mut parts, state).await;

        // Take the Authorization header
        let token_from_header = match header {
            Ok(header) => Some(header.token().to_owned()),
            Err(err) => match err.reason() {
                // If it's missing it is fine
                TypedHeaderRejectionReason::Missing => None,
                // If the header could not be parsed, return the error
                _ => return Err(UserAuthorizationError::InvalidHeader),
            },
        };

        let req = Request::from_parts(parts, body);

        // Take the form value
        let (token_from_form, form) =
            match Form::<AuthorizedForm<F>>::from_request(req, state).await {
                Ok(Form(form)) => (form.access_token, Some(form.inner)),
                // If it is not a form, continue
                Err(FormRejection::InvalidFormContentType(_err)) => (None, None),
                // If the form could not be read, return a Bad Request error
                Err(FormRejection::FailedToDeserializeForm(err)) => {
                    return Err(UserAuthorizationError::BadForm(err))
                }
                // Other errors (body read twice, byte stream broke) return an internal error
                Err(e) => return Err(UserAuthorizationError::Internal(Box::new(e))),
            };

        let access_token = match (token_from_header, token_from_form) {
            // Ensure the token should not be in both the form and the access token
            (Some(_), Some(_)) => return Err(UserAuthorizationError::TokenInFormAndHeader),
            (Some(t), None) => AccessToken::Header(t),
            (None, Some(t)) => AccessToken::Form(t),
            (None, None) => AccessToken::None,
        };

        Ok(UserAuthorization { access_token, form })
    }
}
