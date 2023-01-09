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
use oauth2_types::scope::Scope;
use serde::Serialize;
use ulid::Ulid;

use crate::InvalidTransitionError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    pub id: Ulid,
    pub user_session_id: Ulid,
    pub client_id: Ulid,
    pub scope: Scope,
    pub finished_at: Option<DateTime<Utc>>,
}

impl Session {
    pub fn finish(mut self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        if self.finished_at.is_some() {
            return Err(InvalidTransitionError);
        }

        self.finished_at = Some(finished_at);
        Ok(self)
    }
}
