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
use tracing::info;
use warp::{filters::BoxedFilter, reply::with_header, wrap_fn, Filter, Rejection, Reply};

use crate::{
    config::CsrfConfig,
    csrf::CsrfForm,
    errors::WrapError,
    filters::{csrf::with_csrf, with_pool, with_templates, CsrfToken},
    templates::{CommonContext, Templates},
};

#[derive(Deserialize, Debug)]
struct ReauthForm {
    password: String,
}

pub(super) fn filter(
    pool: PgPool,
    templates: Templates,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(impl Reply,)> {
    // TODO: this is ugly and leaks
    let csrf_cookie_name = Box::leak(Box::new(csrf_config.cookie_name.clone()));

    let get = warp::get()
        .and(with_templates(templates))
        .and(csrf_config.to_extract_filter())
        .and(with_pool(pool.clone()))
        .and_then(get)
        .untuple_one()
        .with(wrap_fn(with_csrf(csrf_config.key, csrf_cookie_name)));

    let post = warp::post()
        .and(csrf_config.to_extract_filter())
        .and(with_pool(pool))
        .and(warp::body::form())
        .and_then(post)
        .untuple_one()
        .with(wrap_fn(with_csrf(csrf_config.key, csrf_cookie_name)));

    warp::path("reauth").and(get.or(post)).boxed()
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

    // TODO: check if there is an existing session
    let content = templates.render("reauth.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}

async fn post(
    csrf_token: CsrfToken,
    _db: PgPool,
    form: CsrfForm<ReauthForm>,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    let form = form.verify_csrf(&csrf_token).wrap_error()?;

    info!(?form, "reauth");

    Ok((csrf_token, "unimplemented"))
}

/*
    let form = form.verify_csrf(&csrf_token).wrap_error()?;

    let _session_info = login(&db, &form.username, &form.password)
        .await
        .wrap_error()?;

    Ok((csrf_token, warp::redirect(Uri::from_static("/"))))
}

pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<ReauthForm> = req.body_form().await?;
    let form = form.verify_csrf(&req)?;
    let state = req.state();
    let session = req.session();

    let session_id = session
        .get("current_session")
        .ok_or_else(|| anyhow::anyhow!("could not find existing session"))?;

    let _session = state
        .storage()
        .lookup_and_reauth_session(session_id, &form.password)
        .await?;

    Ok(Redirect::new("/").into())
}
*/
