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
use oauth2_types::{pkce::CodeChallengeMethodExt, requests::ResponseMode};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use super::{client::Client, session::Session};
use crate::{traits::StorageBackend, StorageBackendMarker};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pkce {
    pub challenge_method: PkceCodeChallengeMethod,
    pub challenge: String,
}

impl Pkce {
    #[must_use]
    pub fn new(challenge_method: PkceCodeChallengeMethod, challenge: String) -> Self {
        Pkce {
            challenge_method,
            challenge,
        }
    }

    #[must_use]
    pub fn verify(&self, verifier: &str) -> bool {
        self.challenge_method.verify(&self.challenge, verifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub pkce: Option<Pkce>,
}

#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend", tag = "stage", rename_all = "lowercase")]
pub enum AuthorizationGrantStage<T: StorageBackend> {
    Pending,
    Fulfilled {
        session: Session<T>,
        fulfilled_at: DateTime<Utc>,
    },
    Exchanged {
        session: Session<T>,
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
    },
    Cancelled {
        cancelled_at: DateTime<Utc>,
    },
}

impl<T: StorageBackend> Default for AuthorizationGrantStage<T> {
    fn default() -> Self {
        Self::Pending
    }
}

impl<T: StorageBackend> AuthorizationGrantStage<T> {
    #[must_use]
    pub fn new() -> Self {
        Self::Pending
    }

    pub fn fulfill(
        self,
        fulfilled_at: DateTime<Utc>,
        session: Session<T>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Fulfilled {
                fulfilled_at,
                session,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    pub fn exchange(self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Fulfilled {
                fulfilled_at,
                session,
            } => Ok(Self::Exchanged {
                fulfilled_at,
                exchanged_at,
                session,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    pub fn cancel(self, cancelled_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Cancelled { cancelled_at }),
            _ => Err(InvalidTransitionError),
        }
    }
}

impl<S: StorageBackendMarker> From<AuthorizationGrantStage<S>> for AuthorizationGrantStage<()> {
    fn from(s: AuthorizationGrantStage<S>) -> Self {
        use AuthorizationGrantStage::{Cancelled, Exchanged, Fulfilled, Pending};
        match s {
            Pending => Pending,
            Fulfilled {
                session,
                fulfilled_at,
            } => Fulfilled {
                session: session.into(),
                fulfilled_at,
            },
            Exchanged {
                session,
                fulfilled_at,
                exchanged_at,
            } => Exchanged {
                session: session.into(),
                fulfilled_at,
                exchanged_at,
            },
            Cancelled { cancelled_at } => Cancelled { cancelled_at },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct AuthorizationGrant<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::AuthorizationGrantData,
    #[serde(flatten)]
    pub stage: AuthorizationGrantStage<T>,
    pub code: Option<AuthorizationCode>,
    pub client: Client<T>,
    pub redirect_uri: Url,
    pub scope: oauth2_types::scope::Scope,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<NonZeroU32>,
    pub acr_values: Option<String>,
    pub response_mode: ResponseMode,
    pub response_type_token: bool,
    pub response_type_id_token: bool,
    pub created_at: DateTime<Utc>,
}

impl<S: StorageBackendMarker> From<AuthorizationGrant<S>> for AuthorizationGrant<()> {
    fn from(g: AuthorizationGrant<S>) -> Self {
        AuthorizationGrant {
            data: (),
            stage: g.stage.into(),
            code: g.code,
            client: g.client.into(),
            redirect_uri: g.redirect_uri,
            scope: g.scope,
            state: g.state,
            nonce: g.nonce,
            max_age: g.max_age,
            acr_values: g.acr_values,
            response_mode: g.response_mode,
            response_type_token: g.response_type_token,
            response_type_id_token: g.response_type_id_token,
            created_at: g.created_at,
        }
    }
}

impl<T: StorageBackend> AuthorizationGrant<T> {
    pub fn max_auth_time(&self) -> DateTime<Utc> {
        let max_age: Option<i64> = self.max_age.map(|x| x.get().into());
        self.created_at - Duration::seconds(max_age.unwrap_or(3600 * 24 * 365))
    }
}
