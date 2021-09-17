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

use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, Executor, PgPool, Postgres};
use warp::{Filter, Rejection};

use super::{
    cookies::{encrypted, maybe_encrypted, EncryptableCookieValue},
    database::with_connection,
};
use crate::{
    config::CookiesConfig,
    errors::WrapError,
    storage::{lookup_active_session, SessionInfo},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionCookie {
    current: i64,
}

impl SessionCookie {
    #[must_use]
    pub fn from_session_info(info: &SessionInfo) -> Self {
        Self {
            current: info.key(),
        }
    }

    pub async fn load_session_info(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> anyhow::Result<SessionInfo> {
        let res = lookup_active_session(executor, self.current).await?;
        Ok(res)
    }
}

impl EncryptableCookieValue for SessionCookie {
    fn cookie_key() -> &'static str {
        "session"
    }
}

#[must_use]
pub fn with_optional_session(
    pool: &PgPool,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (Option<SessionInfo>,), Error = Rejection> + Clone + Send + Sync + 'static
{
    maybe_encrypted(cookies_config)
        .and(with_connection(pool))
        .and_then(
            |maybe_session: Option<SessionCookie>, mut conn: PoolConnection<Postgres>| async move {
                let maybe_session_info = if let Some(session) = maybe_session {
                    session.load_session_info(&mut conn).await.ok()
                } else {
                    None
                };
                Ok::<_, Rejection>(maybe_session_info)
            },
        )
}

#[must_use]
pub fn with_session(
    pool: &PgPool,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (SessionInfo,), Error = Rejection> + Clone + Send + Sync + 'static {
    encrypted(cookies_config)
        .and(with_connection(pool))
        .and_then(
            |session: SessionCookie, mut conn: PoolConnection<Postgres>| async move {
                let session_info = session.load_session_info(&mut conn).await.wrap_error()?;
                Ok::<_, Rejection>(session_info)
            },
        )
}
