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

//! Load user sessions from the database

use mas_config::Encrypter;
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{lookup_active_session, ActiveSessionLookupError},
    PostgresqlBackend,
};
use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, Executor, PgPool, Postgres};
use thiserror::Error;
use tracing::warn;
use warp::{
    reject::{InvalidHeader, MissingCookie, Reject},
    Filter, Rejection,
};

use super::{
    cookies::{encrypted, CookieDecryptionError, EncryptableCookieValue},
    database::connection,
    none_on_error,
};

/// The session is missing or failed to load
#[derive(Error, Debug)]
pub enum SessionLoadError {
    /// No session cookie was found
    #[error("missing session cookie")]
    MissingCookie,

    /// The session cookie is invalid
    #[error("unable to parse or decrypt session cookie")]
    InvalidCookie,

    /// The session is unknown or inactive
    #[error("unknown or inactive session")]
    UnknownSession,
}

impl Reject for SessionLoadError {}

/// An encrypted cookie to save the session ID
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionCookie {
    current: i64,
}

impl SessionCookie {
    /// Forge the cookie from a [`BrowserSession`]
    #[must_use]
    pub fn from_session(session: &BrowserSession<PostgresqlBackend>) -> Self {
        Self {
            current: session.data,
        }
    }

    /// Load the [`BrowserSession`] from database
    pub async fn load_session(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> Result<BrowserSession<PostgresqlBackend>, ActiveSessionLookupError> {
        let res = lookup_active_session(executor, self.current).await?;
        Ok(res)
    }
}

impl EncryptableCookieValue for SessionCookie {
    fn cookie_key() -> &'static str {
        "session"
    }
}

/// Extract a user session information if logged in
#[must_use]
pub fn optional_session(
    pool: &PgPool,
    encrypter: &Encrypter,
) -> impl Filter<Extract = (Option<BrowserSession<PostgresqlBackend>>,), Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    session(pool, encrypter)
        .map(Some)
        .recover(none_on_error::<_, SessionLoadError>)
        .unify()
}

/// Extract a user session information, rejecting if not logged in
///
/// # Rejections
///
/// This filter will reject with a [`SessionLoadError`] when the session is
/// inactive or missing. It will reject with a wrapped error on other database
/// failures.
#[must_use]
pub fn session(
    pool: &PgPool,
    encrypter: &Encrypter,
) -> impl Filter<Extract = (BrowserSession<PostgresqlBackend>,), Error = Rejection>
       + Clone
       + Send
       + Sync
       + 'static {
    encrypted(encrypter)
        .and(connection(pool))
        .and_then(load_session)
        .recover(recover)
        .unify()
}

async fn load_session(
    session: SessionCookie,
    mut conn: PoolConnection<Postgres>,
) -> Result<BrowserSession<PostgresqlBackend>, Rejection> {
    let session_info = session.load_session(&mut conn).await?;
    Ok(session_info)
}

/// Recover from expected rejections, to transform them into a
/// [`SessionLoadError`]
async fn recover<T>(rejection: Rejection) -> Result<T, Rejection> {
    if let Some(e) = rejection.find::<ActiveSessionLookupError>() {
        if e.not_found() {
            return Err(warp::reject::custom(SessionLoadError::UnknownSession));
        }

        // If we're here, there is a real database error that should be
        // propagated
    }

    if let Some(e) = rejection.find::<InvalidHeader>() {
        if e.name() == "cookie" {
            return Err(warp::reject::custom(SessionLoadError::MissingCookie));
        }
    }

    if let Some(_e) = rejection.find::<MissingCookie>() {
        return Err(warp::reject::custom(SessionLoadError::MissingCookie));
    }

    if let Some(error) = rejection.find::<CookieDecryptionError<SessionCookie>>() {
        warn!(?error, "could not decrypt session cookie");
        return Err(warp::reject::custom(SessionLoadError::InvalidCookie));
    }

    Err(rejection)
}
