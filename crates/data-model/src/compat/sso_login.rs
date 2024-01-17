// Copyright 2023 The Matrix.org Foundation C.I.C.
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
use ulid::Ulid;
use url::Url;

use super::CompatSession;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum CompatSsoLoginState {
    #[default]
    Pending,
    Fulfilled {
        fulfilled_at: DateTime<Utc>,
        session_id: Ulid,
    },
    Exchanged {
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
        session_id: Ulid,
    },
}

impl CompatSsoLoginState {
    /// Returns `true` if the compat SSO login state is [`Pending`].
    ///
    /// [`Pending`]: CompatSsoLoginState::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the compat SSO login state is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: CompatSsoLoginState::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the compat SSO login state is [`Exchanged`].
    ///
    /// [`Exchanged`]: CompatSsoLoginState::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }

    /// Get the time at which the login was fulfilled.
    ///
    /// Returns `None` if the compat SSO login state is [`Pending`].
    ///
    /// [`Pending`]: CompatSsoLoginState::Pending
    #[must_use]
    pub fn fulfilled_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending => None,
            Self::Fulfilled { fulfilled_at, .. } | Self::Exchanged { fulfilled_at, .. } => {
                Some(*fulfilled_at)
            }
        }
    }

    /// Get the time at which the login was exchanged.
    ///
    /// Returns `None` if the compat SSO login state is not [`Exchanged`].
    ///
    /// [`Exchanged`]: CompatSsoLoginState::Exchanged
    #[must_use]
    pub fn exchanged_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending | Self::Fulfilled { .. } => None,
            Self::Exchanged { exchanged_at, .. } => Some(*exchanged_at),
        }
    }

    /// Get the session ID associated with the login.
    ///
    /// Returns `None` if the compat SSO login state is [`Pending`].
    ///
    /// [`Pending`]: CompatSsoLoginState::Pending
    #[must_use]
    pub fn session_id(&self) -> Option<Ulid> {
        match self {
            Self::Pending => None,
            Self::Fulfilled { session_id, .. } | Self::Exchanged { session_id, .. } => {
                Some(*session_id)
            }
        }
    }

    /// Transition the compat SSO login state from [`Pending`] to [`Fulfilled`].
    ///
    /// # Errors
    ///
    /// Returns an error if the compat SSO login state is not [`Pending`].
    ///
    /// [`Pending`]: CompatSsoLoginState::Pending
    /// [`Fulfilled`]: CompatSsoLoginState::Fulfilled
    pub fn fulfill(
        self,
        fulfilled_at: DateTime<Utc>,
        session: &CompatSession,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Fulfilled {
                fulfilled_at,
                session_id: session.id,
            }),
            Self::Fulfilled { .. } | Self::Exchanged { .. } => Err(InvalidTransitionError),
        }
    }

    /// Transition the compat SSO login state from [`Fulfilled`] to
    /// [`Exchanged`].
    ///
    /// # Errors
    ///
    /// Returns an error if the compat SSO login state is not [`Fulfilled`].
    ///
    /// [`Fulfilled`]: CompatSsoLoginState::Fulfilled
    /// [`Exchanged`]: CompatSsoLoginState::Exchanged
    pub fn exchange(self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Fulfilled {
                fulfilled_at,
                session_id,
            } => Ok(Self::Exchanged {
                fulfilled_at,
                exchanged_at,
                session_id,
            }),
            Self::Pending { .. } | Self::Exchanged { .. } => Err(InvalidTransitionError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatSsoLogin {
    pub id: Ulid,
    pub redirect_uri: Url,
    pub login_token: String,
    pub created_at: DateTime<Utc>,
    pub state: CompatSsoLoginState,
}

impl std::ops::Deref for CompatSsoLogin {
    type Target = CompatSsoLoginState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl CompatSsoLogin {
    /// Transition the compat SSO login from a [`Pending`] state to
    /// [`Fulfilled`].
    ///
    /// # Errors
    ///
    /// Returns an error if the compat SSO login state is not [`Pending`].
    ///
    /// [`Pending`]: CompatSsoLoginState::Pending
    /// [`Fulfilled`]: CompatSsoLoginState::Fulfilled
    pub fn fulfill(
        mut self,
        fulfilled_at: DateTime<Utc>,
        session: &CompatSession,
    ) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.fulfill(fulfilled_at, session)?;
        Ok(self)
    }

    /// Transition the compat SSO login from a [`Fulfilled`] state to
    /// [`Exchanged`].
    ///
    /// # Errors
    ///
    /// Returns an error if the compat SSO login state is not [`Fulfilled`].
    ///
    /// [`Fulfilled`]: CompatSsoLoginState::Fulfilled
    /// [`Exchanged`]: CompatSsoLoginState::Exchanged
    pub fn exchange(mut self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.exchange(exchanged_at)?;
        Ok(self)
    }
}
