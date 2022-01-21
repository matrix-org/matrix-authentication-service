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

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::traits::{StorageBackend, StorageBackendMarker};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct User<T: StorageBackend> {
    pub data: T::UserData,
    pub username: String,
    pub sub: String,
    pub primary_email: Option<UserEmail<T>>,
}

impl<T: StorageBackend> User<T>
where
    T::UserData: Default,
{
    #[must_use]
    pub fn samples() -> Vec<Self> {
        vec![User {
            data: Default::default(),
            username: "john".to_string(),
            sub: "123-456".to_string(),
            primary_email: None,
        }]
    }
}

impl<S: StorageBackendMarker> From<User<S>> for User<()> {
    fn from(u: User<S>) -> Self {
        User {
            data: (),
            username: u.username,
            sub: u.sub,
            primary_email: u.primary_email.map(Into::into),
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
    #[must_use]
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
pub struct UserEmail<T: StorageBackend> {
    pub data: T::UserEmailData,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

impl<S: StorageBackendMarker> From<UserEmail<S>> for UserEmail<()> {
    fn from(e: UserEmail<S>) -> Self {
        Self {
            data: (),
            email: e.email,
            created_at: e.created_at,
            confirmed_at: e.confirmed_at,
        }
    }
}

impl<T: StorageBackend> UserEmail<T>
where
    T::UserEmailData: Default,
{
    #[must_use]
    pub fn samples() -> Vec<Self> {
        vec![
            Self {
                data: T::UserEmailData::default(),
                email: "alice@example.com".to_string(),
                created_at: Utc::now(),
                confirmed_at: Some(Utc::now()),
            },
            Self {
                data: T::UserEmailData::default(),
                email: "bob@example.com".to_string(),
                created_at: Utc::now(),
                confirmed_at: None,
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum UserEmailVerificationState {
    AlreadyUsed { when: DateTime<Utc> },
    Expired,
    Valid,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct UserEmailVerification<T: StorageBackend> {
    pub data: T::UserEmailVerificationData,
    pub email: UserEmail<T>,
    pub created_at: DateTime<Utc>,
    pub state: UserEmailVerificationState,
}

impl<S: StorageBackendMarker> From<UserEmailVerification<S>> for UserEmailVerification<()> {
    fn from(v: UserEmailVerification<S>) -> Self {
        Self {
            data: (),
            email: v.email.into(),
            created_at: v.created_at,
            state: v.state,
        }
    }
}

impl<T: StorageBackend> UserEmailVerification<T>
where
    T::UserEmailData: Default + Clone,
{
    #[must_use]
    pub fn samples() -> Vec<Self> {
        let states = [
            UserEmailVerificationState::AlreadyUsed {
                when: Utc::now() - Duration::minutes(5),
            },
            UserEmailVerificationState::Expired,
            UserEmailVerificationState::Valid,
        ];

        states
            .into_iter()
            .flat_map(|state| {
                UserEmail::samples().into_iter().map(move |email| Self {
                    data: Default::default(),
                    email,
                    created_at: Utc::now() - Duration::minutes(10),
                    state: state.clone(),
                })
            })
            .collect()
    }
}
