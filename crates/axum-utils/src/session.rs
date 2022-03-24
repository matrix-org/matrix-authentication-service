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

use cookie::Cookie;
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{lookup_active_session, ActiveSessionLookupError},
    PostgresqlBackend,
};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, Postgres};

use crate::{CookieExt, PrivateCookieJar};

/// An encrypted cookie to save the session ID
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SessionInfo {
    current: Option<i64>,
}

impl SessionInfo {
    /// Forge the cookie from a [`BrowserSession`]
    #[must_use]
    pub fn from_session(session: &BrowserSession<PostgresqlBackend>) -> Self {
        Self {
            current: Some(session.data),
        }
    }

    /// Load the [`BrowserSession`] from database
    pub async fn load_session(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> Result<Option<BrowserSession<PostgresqlBackend>>, ActiveSessionLookupError> {
        let session_id = if let Some(id) = self.current {
            id
        } else {
            return Ok(None);
        };

        let res = lookup_active_session(executor, session_id).await?;
        Ok(Some(res))
    }
}

pub trait SessionInfoExt {
    fn session_info(self) -> (SessionInfo, Self);
    fn update_session_info(self, info: &SessionInfo) -> Self;
    fn set_session(self, session: &BrowserSession<PostgresqlBackend>) -> Self
    where
        Self: Sized,
    {
        let session_info = SessionInfo::from_session(session);
        self.update_session_info(&session_info)
    }
}

impl<K> SessionInfoExt for PrivateCookieJar<K> {
    fn session_info(self) -> (SessionInfo, Self) {
        let jar = self;
        let cookie = jar
            .get("session")
            .unwrap_or_else(|| Cookie::new("session", ""));
        let session_info = cookie.decode().unwrap_or_default();

        let cookie = cookie.encode(&session_info);
        let jar = jar.add(cookie);
        (session_info, jar)
    }

    fn update_session_info(self, info: &SessionInfo) -> Self {
        let cookie = Cookie::new("session", "");
        let cookie = cookie.encode(&info);
        self.add(cookie)
    }
}
