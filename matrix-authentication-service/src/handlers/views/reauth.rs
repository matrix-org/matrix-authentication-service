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

use serde::Deserialize;
use sqlx::PgPool;
use warp::{
    filters::BoxedFilter, hyper::Uri, reply::with_header, wrap_fn, Filter, Rejection, Reply,
};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::WrapError,
    filters::{
        csrf::{protected_form, save_csrf_token, updated_csrf_token},
        session::with_session,
        with_pool, with_templates, CsrfToken,
    },
    storage::SessionInfo,
    templates::{CommonContext, Templates},
};

#[derive(Deserialize, Debug)]
struct ReauthForm {
    password: String,
}

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(impl Reply,)> {
    let get = warp::get()
        .and(with_templates(templates))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(with_session(pool, cookies_config))
        .and_then(get)
        .untuple_one()
        .with(wrap_fn(save_csrf_token(cookies_config)));

    let post = warp::post()
        .and(with_session(pool, cookies_config))
        .and(with_pool(pool))
        .and(protected_form(cookies_config))
        .and_then(post);

    warp::path("reauth").and(get.or(post)).boxed()
}

async fn get(
    templates: Templates,
    csrf_token: CsrfToken,
    session: SessionInfo,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    let ctx = CommonContext::default()
        .with_csrf_token(&csrf_token)
        .with_session(session)
        .finish()
        .wrap_error()?;

    let content = templates.render("reauth.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}

async fn post(
    session: SessionInfo,
    pool: PgPool,
    form: ReauthForm,
) -> Result<impl Reply, Rejection> {
    let _session = session.reauth(&pool, &form.password).await.wrap_error()?;

    Ok(warp::redirect(Uri::from_static("/")))
}
