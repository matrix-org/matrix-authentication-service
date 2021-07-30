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
use warp::{filters::BoxedFilter, reply::with_header, wrap_fn, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::WrapError,
    filters::{
        csrf::{save_csrf_token, updated_csrf_token},
        session::with_optional_session,
        with_templates, CsrfToken,
    },
    storage::SessionInfo,
    templates::{CommonContext, Templates},
};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(impl Reply,)> {
    warp::get()
        .and(warp::path::end())
        .and(with_templates(templates))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(with_optional_session(pool, cookies_config))
        .and_then(get)
        .untuple_one()
        .with(wrap_fn(save_csrf_token(cookies_config)))
        .boxed()
}

async fn get(
    templates: Templates,
    csrf_token: CsrfToken,
    session: Option<SessionInfo>,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    let ctx = CommonContext::default()
        .with_csrf_token(&csrf_token)
        .maybe_with_session(session)
        .finish()
        .wrap_error()?;

    let content = templates.render("index.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}
