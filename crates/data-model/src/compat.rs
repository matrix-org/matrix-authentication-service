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

use chrono::{DateTime, Utc};
use oauth2_types::scope::ScopeToken;
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use crate::User;

static DEVICE_ID_LENGTH: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Device {
    id: String,
}

#[derive(Debug, Error)]
pub enum InvalidDeviceID {
    #[error("Device ID does not have the right size")]
    InvalidLength,

    #[error("Device ID contains invalid characters")]
    InvalidCharacters,
}

impl Device {
    /// Get the corresponding [`ScopeToken`] for that device
    #[must_use]
    pub fn to_scope_token(&self) -> ScopeToken {
        // SAFETY: the inner id should only have valid scope characters
        format!("urn:matrix:org.matrix.msc2967.client:device:{}", self.id)
            .parse()
            .unwrap()
    }

    /// Generate a random device ID
    pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let id: String = Alphanumeric.sample_string(rng, DEVICE_ID_LENGTH);
        Self { id }
    }

    /// Get the inner device ID as [`&str`]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl TryFrom<String> for Device {
    type Error = InvalidDeviceID;

    /// Create a [`Device`] out of an ID, validating the ID has the right shape
    fn try_from(id: String) -> Result<Self, Self::Error> {
        if id.len() != DEVICE_ID_LENGTH {
            return Err(InvalidDeviceID::InvalidLength);
        }

        if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(InvalidDeviceID::InvalidCharacters);
        }

        Ok(Self { id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatSession {
    pub id: Ulid,
    pub user: User,
    pub device: Device,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatAccessToken {
    pub id: Ulid,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatRefreshToken {
    pub id: Ulid,
    pub token: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CompatSsoLoginState {
    Pending,
    Fulfilled {
        fulfilled_at: DateTime<Utc>,
        session: CompatSession,
    },
    Exchanged {
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
        session: CompatSession,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatSsoLogin {
    pub id: Ulid,
    pub redirect_uri: Url,
    pub login_token: String,
    pub created_at: DateTime<Utc>,
    pub state: CompatSsoLoginState,
}
