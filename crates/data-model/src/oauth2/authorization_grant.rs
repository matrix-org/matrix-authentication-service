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

use std::num::NonZeroU32;

use chrono::{DateTime, Duration, Utc};
use mas_iana::oauth::PkceCodeChallengeMethod;
use oauth2_types::{
    pkce::{CodeChallengeError, CodeChallengeMethodExt},
    requests::ResponseMode,
    scope::{Scope, OPENID, PROFILE},
};
use rand::{
    distributions::{Alphanumeric, DistString},
    RngCore,
};
use serde::Serialize;
use ulid::Ulid;
use url::Url;

use super::session::Session;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pkce {
    pub challenge_method: PkceCodeChallengeMethod,
    pub challenge: String,
}

impl Pkce {
    /// Create a new PKCE challenge, with the given method and challenge.
    #[must_use]
    pub fn new(challenge_method: PkceCodeChallengeMethod, challenge: String) -> Self {
        Pkce {
            challenge_method,
            challenge,
        }
    }

    /// Verify the PKCE challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier is invalid.
    pub fn verify(&self, verifier: &str) -> Result<(), CodeChallengeError> {
        self.challenge_method.verify(&self.challenge, verifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub pkce: Option<Pkce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "stage", rename_all = "lowercase")]
pub enum AuthorizationGrantStage {
    #[default]
    Pending,
    Fulfilled {
        session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
    },
    Exchanged {
        session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
    },
    Cancelled {
        cancelled_at: DateTime<Utc>,
    },
}

impl AuthorizationGrantStage {
    #[must_use]
    pub fn new() -> Self {
        Self::Pending
    }

    fn fulfill(
        self,
        fulfilled_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Fulfilled {
                fulfilled_at,
                session_id: session.id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    fn exchange(self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Fulfilled {
                fulfilled_at,
                session_id,
            } => Ok(Self::Exchanged {
                fulfilled_at,
                exchanged_at,
                session_id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    fn cancel(self, cancelled_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Cancelled { cancelled_at }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the authorization grant stage is [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the authorization grant stage is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the authorization grant stage is [`Exchanged`].
    ///
    /// [`Exchanged`]: AuthorizationGrantStage::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationGrant {
    pub id: Ulid,
    #[serde(flatten)]
    pub stage: AuthorizationGrantStage,
    pub code: Option<AuthorizationCode>,
    pub client_id: Ulid,
    pub redirect_uri: Url,
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<NonZeroU32>,
    pub response_mode: ResponseMode,
    pub response_type_id_token: bool,
    pub created_at: DateTime<Utc>,
    pub requires_consent: bool,
}

impl std::ops::Deref for AuthorizationGrant {
    type Target = AuthorizationGrantStage;

    fn deref(&self) -> &Self::Target {
        &self.stage
    }
}

impl AuthorizationGrant {
    #[must_use]
    pub fn max_auth_time(&self) -> DateTime<Utc> {
        let max_age: Option<i64> = self.max_age.map(|x| x.get().into());
        self.created_at - Duration::seconds(max_age.unwrap_or(3600 * 24 * 365))
    }

    /// Mark the authorization grant as exchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    pub fn exchange(mut self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.exchange(exchanged_at)?;
        Ok(self)
    }

    /// Mark the authorization grant as fulfilled.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    pub fn fulfill(
        mut self,
        fulfilled_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.fulfill(fulfilled_at, session)?;
        Ok(self)
    }

    /// Mark the authorization grant as cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    ///
    /// # TODO
    ///
    /// This appears to be unused
    pub fn cancel(mut self, canceld_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.cancel(canceld_at)?;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn sample(now: DateTime<Utc>, rng: &mut impl RngCore) -> Self {
        Self {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            stage: AuthorizationGrantStage::Pending,
            code: Some(AuthorizationCode {
                code: Alphanumeric.sample_string(rng, 10),
                pkce: None,
            }),
            client_id: Ulid::from_datetime_with_source(now.into(), rng),
            redirect_uri: Url::parse("http://localhost:8080").unwrap(),
            scope: Scope::from_iter([OPENID, PROFILE]),
            state: Some(Alphanumeric.sample_string(rng, 10)),
            nonce: Some(Alphanumeric.sample_string(rng, 10)),
            max_age: None,
            response_mode: ResponseMode::Query,
            response_type_id_token: false,
            created_at: now,
            requires_consent: false,
        }
    }
}
