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

use crate::traits::{StorageBackend, StorageBackendMarker};

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
