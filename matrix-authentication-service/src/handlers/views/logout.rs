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

use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{hyper::Uri, Filter, Rejection, Reply};

use crate::{
    config::CookiesConfig,
    errors::WrapError,
    filters::{csrf::protected_form, database::with_connection, session::with_session},
    storage::SessionInfo,
};

pub(super) fn filter(
    pool: &PgPool,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("logout")
        .and(warp::post())
        .and(with_session(pool, cookies_config))
        .and(with_connection(pool))
        .and(protected_form(cookies_config))
        .and_then(post)
}

async fn post(
    session: SessionInfo,
    mut conn: PoolConnection<Postgres>,
    _form: (),
) -> Result<impl Reply, Rejection> {
    session.end(&mut conn).await.wrap_error()?;
    Ok::<_, Rejection>(warp::redirect(Uri::from_static("/login")))
}
