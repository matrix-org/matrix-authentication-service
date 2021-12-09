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

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::traits::{StorageBackend, StorageBackendMarker};

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
    #[must_use]
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
