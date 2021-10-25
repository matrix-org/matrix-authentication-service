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
use oauth2_types::{pkce::CodeChallengeMethod, requests::ResponseMode, scope::Scope};
use serde::Serialize;
use thiserror::Error;
use url::Url;

pub mod errors;

pub trait StorageBackendMarker: StorageBackend {}

pub trait StorageBackend {
    type UserData: Clone + std::fmt::Debug + PartialEq;
    type AuthenticationData: Clone + std::fmt::Debug + PartialEq;
    type BrowserSessionData: Clone + std::fmt::Debug + PartialEq;
    type ClientData: Clone + std::fmt::Debug + PartialEq;
    type SessionData: Clone + std::fmt::Debug + PartialEq;
    type AuthorizationGrantData: Clone + std::fmt::Debug + PartialEq;
    type AccessTokenData: Clone + std::fmt::Debug + PartialEq;
    type RefreshTokenData: Clone + std::fmt::Debug + PartialEq;
}

impl StorageBackend for () {
    type AccessTokenData = ();
    type AuthenticationData = ();
    type AuthorizationGrantData = ();
    type BrowserSessionData = ();
    type ClientData = ();
    type RefreshTokenData = ();
    type SessionData = ();
    type UserData = ();
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct User<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::UserData,
    pub username: String,
    pub sub: String,
}

impl<T: StorageBackend> User<T>
where
    T::UserData: Default,
{
    pub fn samples() -> Vec<Self> {
        vec![User {
            data: Default::default(),
            username: "john".to_string(),
            sub: "123-456".to_string(),
        }]
    }
}

impl<S: StorageBackendMarker> From<User<S>> for User<()> {
    fn from(u: User<S>) -> Self {
        User {
            data: (),
            username: u.username,
            sub: u.sub,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Authentication<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::AuthenticationData,
    pub created_at: DateTime<Utc>,
}

impl<S: StorageBackendMarker> From<Authentication<S>> for Authentication<()> {
    fn from(a: Authentication<S>) -> Self {
        Authentication {
            data: (),
            created_at: a.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct BrowserSession<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::BrowserSessionData,
    pub user: User<T>,
    pub created_at: DateTime<Utc>,
    pub last_authentication: Option<Authentication<T>>,
}

impl<S: StorageBackendMarker> From<BrowserSession<S>> for BrowserSession<()> {
    fn from(s: BrowserSession<S>) -> Self {
        BrowserSession {
            data: (),
            user: s.user.into(),
            created_at: s.created_at,
            last_authentication: s.last_authentication.map(Into::into),
        }
    }
}

impl<T: StorageBackend> BrowserSession<T>
where
    T::BrowserSessionData: Default,
    T::UserData: Default,
{
    pub fn samples() -> Vec<Self> {
        User::<T>::samples()
            .into_iter()
            .map(|user| BrowserSession {
                data: Default::default(),
                user,
                created_at: Utc::now(),
                last_authentication: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Client<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::ClientData,
    pub client_id: String,
}

impl<S: StorageBackendMarker> From<Client<S>> for Client<()> {
    fn from(c: Client<S>) -> Self {
        Client {
            data: (),
            client_id: c.client_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Session<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::SessionData,
    pub browser_session: BrowserSession<T>,
    pub client: Client<T>,
    pub scope: Scope,
}

impl<S: StorageBackendMarker> From<Session<S>> for Session<()> {
    fn from(s: Session<S>) -> Self {
        Session {
            data: (),
            browser_session: s.browser_session.into(),
            client: s.client.into(),
            scope: s.scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken<T: StorageBackend> {
    pub data: T::AccessTokenData,
    pub jti: String,
    pub token: String,
    pub expires_after: Duration,
    pub created_at: DateTime<Utc>,
}

impl<S: StorageBackendMarker> From<AccessToken<S>> for AccessToken<()> {
    fn from(t: AccessToken<S>) -> Self {
        AccessToken {
            data: (),
            jti: t.jti,
            token: t.token,
            expires_after: t.expires_after,
            created_at: t.created_at,
        }
    }
}

impl<T: StorageBackend> AccessToken<T> {
    pub fn exp(&self) -> DateTime<Utc> {
        self.created_at + self.expires_after
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefreshToken<T: StorageBackend> {
    pub data: T::RefreshTokenData,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub access_token: Option<AccessToken<T>>,
}

impl<S: StorageBackendMarker> From<RefreshToken<S>> for RefreshToken<()> {
    fn from(t: RefreshToken<S>) -> Self {
        RefreshToken {
            data: (),
            token: t.token,
            created_at: t.created_at,
            access_token: t.access_token.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pkce {
    pub challenge_method: CodeChallengeMethod,
    pub challenge: String,
}

impl Pkce {
    pub fn new(challenge_method: CodeChallengeMethod, challenge: String) -> Self {
        Pkce {
            challenge_method,
            challenge,
        }
    }

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
#[serde(bound = "T: StorageBackend")]
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
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<NonZeroU32>,
    pub acr_values: Option<String>,
    pub response_mode: ResponseMode,
    pub response_type_token: bool,
    pub response_type_id_token: bool,
    pub created_at: DateTime<Utc>,
}

impl<T: StorageBackend> AuthorizationGrant<T> {
    pub fn max_auth_time(&self) -> DateTime<Utc> {
        let max_age: Option<i64> = self.max_age.map(|x| x.get().into());
        self.created_at + Duration::seconds(max_age.unwrap_or(3600 * 24 * 365))
    }
}
