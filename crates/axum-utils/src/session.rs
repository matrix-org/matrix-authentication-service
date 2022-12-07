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

use axum_extra::extract::cookie::{Cookie, PrivateCookieJar};
use mas_data_model::BrowserSession;
use mas_storage::{user::lookup_active_session, DatabaseError};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, Postgres};
use ulid::Ulid;

use crate::CookieExt;

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
    pub async fn load_session(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> Result<Option<BrowserSession>, DatabaseError> {
        let session_id = if let Some(id) = self.current {
            id
        } else {
            return Ok(None);
        };

        let res = lookup_active_session(executor, session_id).await?;
        Ok(res)
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

impl<K> SessionInfoExt for PrivateCookieJar<K> {
    fn session_info(self) -> (SessionInfo, Self) {
        let jar = self;
        let mut cookie = jar
            .get("session")
            .unwrap_or_else(|| Cookie::new("session", ""));
        cookie.set_path("/");
        cookie.set_http_only(true);
        let session_info = cookie.decode().unwrap_or_default();

        let cookie = cookie.encode(&session_info);
        let jar = jar.add(cookie);
        (session_info, jar)
    }

    fn update_session_info(self, info: &SessionInfo) -> Self {
        let mut cookie = Cookie::new("session", "");
        cookie.set_path("/");
        cookie.set_http_only(true);
        let cookie = cookie.encode(&info);
        self.add(cookie)
    }
}
