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

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

use super::Device;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum CompatSessionState {
    #[default]
    Valid,
    Finished {
        finished_at: DateTime<Utc>,
    },
}

impl CompatSessionState {
    /// Returns `true` if the compat session state is [`Valid`].
    ///
    /// [`Valid`]: CompatSessionState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the compat session state is [`Finished`].
    ///
    /// [`Finished`]: CompatSessionState::Finished
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Finished { .. })
    }

    /// Transitions the session state to [`Finished`].
    ///
    /// # Parameters
    ///
    /// * `finished_at` - The time at which the session was finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the session state is already [`Finished`].
    ///
    /// [`Finished`]: CompatSessionState::Finished
    pub fn finish(self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Finished { finished_at }),
            Self::Finished { .. } => Err(InvalidTransitionError),
        }
    }

    #[must_use]
    pub fn finished_at(&self) -> Option<DateTime<Utc>> {
        match self {
            CompatSessionState::Valid => None,
            CompatSessionState::Finished { finished_at } => Some(*finished_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatSession {
    pub id: Ulid,
    pub state: CompatSessionState,
    pub user_id: Ulid,
    pub device: Device,
    pub user_session_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
    pub is_synapse_admin: bool,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl std::ops::Deref for CompatSession {
    type Target = CompatSessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl CompatSession {
    /// Marks the session as finished.
    ///
    /// # Parameters
    ///
    /// * `finished_at` - The time at which the session was finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is already finished.
    pub fn finish(mut self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.finish(finished_at)?;
        Ok(self)
    }
}
