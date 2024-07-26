// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use std::convert::Infallible;

use aide::OperationIo;
use axum::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::TypedHeader;
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use mas_data_model::{Session, User};
use mas_storage::{BoxClock, BoxRepository, RepositoryError};
use ulid::Ulid;

use super::response::ErrorResponse;
use crate::BoundActivityTracker;

#[derive(Debug, thiserror::Error)]
pub enum Rejection {
    /// The authorization header is missing
    #[error("Missing authorization header")]
    MissingAuthorizationHeader,

    /// The authorization header is invalid
    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,

    /// Couldn't load the database repository
    #[error("Couldn't load the database repository")]
    RepositorySetup(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// A database operation failed
    #[error("Invalid repository operation")]
    Repository(#[from] RepositoryError),

    /// The access token could not be found in the database
    #[error("Unknown access token")]
    UnknownAccessToken,

    /// The access token provided expired
    #[error("Access token expired")]
    TokenExpired,

    /// The session associated with the access token was revoked
    #[error("Access token revoked")]
    SessionRevoked,

    /// The user associated with the session is locked
    #[error("User locked")]
    UserLocked,

    /// Failed to load the session
    #[error("Failed to load session {0}")]
    LoadSession(Ulid),

    /// Failed to load the user
    #[error("Failed to load user {0}")]
    LoadUser(Ulid),

    /// The session does not have the `urn:mas:admin` scope
    #[error("Missing urn:mas:admin scope")]
    MissingScope,
}

impl Rejection {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidAuthorizationHeader | Self::MissingAuthorizationHeader => {
                StatusCode::BAD_REQUEST
            }
            Self::UnknownAccessToken
            | Self::TokenExpired
            | Self::SessionRevoked
            | Self::UserLocked
            | Self::MissingScope => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let response = ErrorResponse::from_error(&self);
        let status = self.status_code();
        (status, Json(response)).into_response()
    }
}

/// An extractor which authorizes the request
///
/// Because we need to load the database repository and the clock, we keep them
/// in the context to avoid creating two instances for each request.
#[non_exhaustive]
#[derive(OperationIo)]
#[aide(input)]
pub struct CallContext {
    pub repo: BoxRepository,
    pub clock: BoxClock,
    pub user: Option<User>,
    pub session: Session,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for CallContext
where
    S: Send + Sync,
    BoundActivityTracker: FromRequestParts<S, Rejection = Infallible>,
    BoxRepository: FromRequestParts<S>,
    BoxClock: FromRequestParts<S, Rejection = Infallible>,
    <BoxRepository as FromRequestParts<S>>::Rejection:
        Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    type Rejection = Rejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let activity_tracker = BoundActivityTracker::from_request_parts(parts, state).await;
        let activity_tracker = match activity_tracker {
            Ok(t) => t,
            Err(e) => match e {},
        };

        let clock = BoxClock::from_request_parts(parts, state).await;
        let clock = match clock {
            Ok(c) => c,
            Err(e) => match e {},
        };

        // Load the database repository
        let mut repo = BoxRepository::from_request_parts(parts, state)
            .await
            .map_err(Into::into)
            .map_err(Rejection::RepositorySetup)?;

        // Extract the access token from the authorization header
        let token = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                // We map to two differentsson of errors depending on whether the header is
                // missing or invalid
                if e.is_missing() {
                    Rejection::MissingAuthorizationHeader
                } else {
                    Rejection::InvalidAuthorizationHeader
                }
            })?;

        let token = token.token();

        // Look for the access token in the database
        let token = repo
            .oauth2_access_token()
            .find_by_token(token)
            .await?
            .ok_or(Rejection::UnknownAccessToken)?;

        // Look for the associated session in the database
        let session = repo
            .oauth2_session()
            .lookup(token.session_id)
            .await?
            .ok_or_else(|| Rejection::LoadSession(token.session_id))?;

        // Record the activity on the session
        activity_tracker
            .record_oauth2_session(&clock, &session)
            .await;

        // Load the user if there is one
        let user = if let Some(user_id) = session.user_id {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or_else(|| Rejection::LoadUser(user_id))?;
            Some(user)
        } else {
            None
        };

        // If there is a user for this session, check that it is not locked
        if let Some(user) = &user {
            if !user.is_valid() {
                return Err(Rejection::UserLocked);
            }
        }

        if !session.is_valid() {
            return Err(Rejection::SessionRevoked);
        }

        if !token.is_valid(clock.now()) {
            return Err(Rejection::TokenExpired);
        }

        // For now, we only check that the session has the admin scope
        // Later we might want to check other route-specific scopes
        if !session.scope.contains("urn:mas:admin") {
            return Err(Rejection::MissingScope);
        }

        Ok(Self {
            repo,
            clock,
            user,
            session,
        })
    }
}
