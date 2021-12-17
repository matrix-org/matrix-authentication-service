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

use mas_config::CookiesConfig;
use mas_data_model::BrowserSession;
use mas_storage::{user::end_session, PostgresqlBackend};
use mas_warp_utils::{
    errors::WrapError,
    filters::{csrf::protected_form, database::transaction, session::session},
};
use sqlx::{PgPool, Postgres, Transaction};
use warp::{hyper::Uri, Filter, Rejection, Reply};

pub(super) fn filter(
    pool: &PgPool,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("logout")
        .and(warp::post())
        .and(session(pool, cookies_config))
        .and(transaction(pool))
        .and(protected_form(cookies_config))
        .and_then(post)
}

async fn post(
    session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
    _form: (),
) -> Result<impl Reply, Rejection> {
    end_session(&mut txn, &session).await.wrap_error()?;
    txn.commit().await.wrap_error()?;

    Ok(warp::redirect(Uri::from_static("/login")))
}
