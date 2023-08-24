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

use mas_data_model::BrowserSession;
use mas_storage::{user::BrowserSessionRepository, RepositoryAccess};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::cookies::CookieJar;

/// An encrypted cookie to save the session ID
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SessionInfo {
    current: Option<Ulid>,
}

impl SessionInfo {
    /// Forge the cookie from a [`BrowserSession`]
    #[must_use]
    pub fn from_session(session: &BrowserSession) -> Self {
        Self {
            current: Some(session.id),
        }
    }

    /// Mark the session as ended
    #[must_use]
    pub fn mark_session_ended(mut self) -> Self {
        self.current = None;
        self
    }

    /// Load the [`BrowserSession`] from database
    pub async fn load_session<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<BrowserSession>, E> {
        let Some(session_id) = self.current else {
            return Ok(None);
        };

        let maybe_session = repo
            .browser_session()
            .lookup(session_id)
            .await?
            // Ensure that the session is still active
            .filter(BrowserSession::active);

        Ok(maybe_session)
    }
}

pub trait SessionInfoExt {
    #[must_use]
    fn session_info(self) -> (SessionInfo, Self);

    #[must_use]
    fn update_session_info(self, info: &SessionInfo) -> Self;

    #[must_use]
    fn set_session(self, session: &BrowserSession) -> Self
    where
        Self: Sized,
    {
        let session_info = SessionInfo::from_session(session);
        self.update_session_info(&session_info)
    }
}

impl SessionInfoExt for CookieJar {
    fn session_info(self) -> (SessionInfo, Self) {
        let info = match self.load("session") {
            Ok(Some(s)) => s,
            Ok(None) => SessionInfo::default(),
            Err(e) => {
                tracing::error!("failed to load session cookie: {}", e);
                SessionInfo::default()
            }
        };

        let jar = self.update_session_info(&info);
        (info, jar)
    }

    fn update_session_info(self, info: &SessionInfo) -> Self {
        self.save("session", info, true)
    }
}
