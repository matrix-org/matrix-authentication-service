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

use sqlx::PgPool;
use warp::{filters::BoxedFilter, hyper::Uri, wrap_fn, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    csrf::CsrfForm,
    errors::WrapError,
    filters::{csrf::save_csrf_token, session::with_session, with_pool, CsrfToken},
    storage::SessionInfo,
};

pub(super) fn filter(
    pool: &PgPool,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(impl Reply,)> {
    warp::post()
        .and(warp::path("logout"))
        .and(csrf_config.to_extract_filter(cookies_config))
        .and(with_session(pool, cookies_config))
        .and(with_pool(pool))
        .and(warp::body::form())
        .and_then(post)
        .untuple_one()
        .with(wrap_fn(save_csrf_token(cookies_config)))
        .boxed()
}

async fn post(
    token: CsrfToken,
    session: Option<SessionInfo>,
    pool: PgPool,
    form: CsrfForm<()>,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    form.verify_csrf(&token).wrap_error()?;
    // TODO: filter with forced active session
    session.unwrap().end(&pool).await.wrap_error()?;
    Ok::<_, Rejection>((token, warp::redirect(Uri::from_static("/login"))))
}
