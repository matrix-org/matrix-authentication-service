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
    config::CsrfConfig,
    errors::WrapError,
    filters::{csrf::with_csrf, with_pool, with_templates, CsrfToken},
    templates::{CommonContext, Templates},
};

pub(super) fn filter(
    pool: PgPool,
    templates: Templates,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(impl Reply,)> {
    // TODO: this is ugly and leaks
    let csrf_cookie_name = Box::leak(Box::new(csrf_config.cookie_name.clone()));

    warp::get()
        .and(warp::path::end())
        .and(with_templates(templates))
        .and(csrf_config.to_extract_filter())
        .and(with_pool(pool))
        .and_then(get)
        .untuple_one()
        .with(wrap_fn(with_csrf(csrf_config.key, csrf_cookie_name)))
        .boxed()
}

async fn get(
    templates: Templates,
    csrf_token: CsrfToken,
    db: PgPool,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    let ctx = CommonContext::default()
        .with_csrf_token(&csrf_token)
        .load_session(&db)
        .await
        .wrap_error()?
        .finish()
        .wrap_error()?;

    let content = templates.render("index.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}
