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

use super::UpstreamOAuthLink;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum UpstreamOAuthAuthorizationSessionState {
    #[default]
    Pending,
    Completed {
        completed_at: DateTime<Utc>,
        link_id: Ulid,
        id_token: Option<String>,
    },
    Consumed {
        completed_at: DateTime<Utc>,
        consumed_at: DateTime<Utc>,
        link_id: Ulid,
        id_token: Option<String>,
    },
}

impl UpstreamOAuthAuthorizationSessionState {
    pub fn complete(
        self,
        completed_at: DateTime<Utc>,
        link: &UpstreamOAuthLink,
        id_token: Option<String>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Completed {
                completed_at,
                link_id: link.id,
                id_token,
            }),
            Self::Completed { .. } | Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }

    pub fn consume(self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Completed {
                completed_at,
                link_id,
                id_token,
            } => Ok(Self::Consumed {
                completed_at,
                link_id,
                consumed_at,
                id_token,
            }),
            Self::Pending | Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }

    #[must_use]
    pub fn link_id(&self) -> Option<Ulid> {
        match self {
            Self::Pending => None,
            Self::Completed { link_id, .. } | Self::Consumed { link_id, .. } => Some(*link_id),
        }
    }

    #[must_use]
    pub fn completed_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending => None,
            Self::Completed { completed_at, .. } | Self::Consumed { completed_at, .. } => {
                Some(*completed_at)
            }
        }
    }

    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        match self {
            Self::Pending => None,
            Self::Completed { id_token, .. } | Self::Consumed { id_token, .. } => {
                id_token.as_deref()
            }
        }
    }

    #[must_use]
    pub fn consumed_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending | Self::Completed { .. } => None,
            Self::Consumed { consumed_at, .. } => Some(*consumed_at),
        }
    }

    /// Returns `true` if the upstream oauth authorization session state is
    /// [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the upstream oauth authorization session state is
    /// [`Completed`].
    ///
    /// [`Completed`]: UpstreamOAuthAuthorizationSessionState::Completed
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Returns `true` if the upstream oauth authorization session state is
    /// [`Consumed`].
    ///
    /// [`Consumed`]: UpstreamOAuthAuthorizationSessionState::Consumed
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        matches!(self, Self::Consumed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthAuthorizationSession {
    pub id: Ulid,
    pub state: UpstreamOAuthAuthorizationSessionState,
    pub provider_id: Ulid,
    pub state_str: String,
    pub code_challenge_verifier: Option<String>,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
}

impl std::ops::Deref for UpstreamOAuthAuthorizationSession {
    type Target = UpstreamOAuthAuthorizationSessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl UpstreamOAuthAuthorizationSession {
    pub fn complete(
        mut self,
        completed_at: DateTime<Utc>,
        link: &UpstreamOAuthLink,
        id_token: Option<String>,
    ) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.complete(completed_at, link, id_token)?;
        Ok(self)
    }

    pub fn consume(mut self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.consume(consumed_at)?;
        Ok(self)
    }
}
