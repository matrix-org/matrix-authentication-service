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

use headers::SetCookie;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, PgPool, Postgres};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

use super::{
    cookies::{encrypted, maybe_encrypted, save_encrypted, WithTypedHeader},
    with_pool,
};
use crate::{
    config::CookiesConfig,
    errors::WrapError,
    storage::{lookup_active_session, SessionInfo},
};

#[derive(Serialize, Deserialize)]
pub struct Session {
    current: i32,
}

impl Session {
    pub fn from_session_info(info: &SessionInfo) -> Self {
        Self {
            current: info.key(),
        }
    }

    pub async fn load_session_info(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> anyhow::Result<SessionInfo> {
        lookup_active_session(executor, self.current).await
    }
}

pub fn with_optional_session(
    pool: &PgPool,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(Option<SessionInfo>,)> {
    maybe_encrypted("session", cookies_config)
        .and(with_pool(pool))
        .and_then(|maybe_session: Option<Session>, pool: PgPool| async move {
            let maybe_session_info = if let Some(session) = maybe_session {
                session.load_session_info(&pool).await.ok()
            } else {
                None
            };
            Ok::<_, Rejection>(maybe_session_info)
        })
        .boxed()
}

pub fn with_session(pool: &PgPool, cookies_config: &CookiesConfig) -> BoxedFilter<(SessionInfo,)> {
    encrypted("session", cookies_config)
        .and(with_pool(pool))
        .and_then(|session: Session, pool: PgPool| async move {
            let session_info = session.load_session_info(&pool).await.wrap_error()?;
            Ok::<_, Rejection>(session_info)
        })
        .boxed()
}

pub fn save_session<R: Reply, F>(
    cookies_config: &CookiesConfig,
) -> impl Fn(F) -> BoxedFilter<(WithTypedHeader<R, SetCookie>,)>
where
    F: Filter<Extract = (SessionInfo, R), Error = Rejection> + Clone + Send + Sync + 'static,
{
    // This clone might be avoidable
    let cookies_config = cookies_config.clone();
    move |f: F| {
        let f = f
            .map(|session_info, reply| (Session::from_session_info(&session_info), reply))
            .untuple_one();
        save_encrypted("session", &cookies_config)(f)
    }
}
