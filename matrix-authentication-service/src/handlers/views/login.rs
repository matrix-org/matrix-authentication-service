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

use std::convert::TryFrom;

use hyper::http::uri::{Parts, PathAndQuery, Uri};
use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{reply::html, wrap_fn, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::WrapError,
    filters::{
        csrf::{protected_form, save_csrf_token, updated_csrf_token},
        database::with_connection,
        session::{save_session, with_optional_session},
        with_templates, CsrfToken,
    },
    storage::{login, SessionInfo},
    templates::{TemplateContext, Templates},
};

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    next: Option<String>,
}

impl LoginRequest {
    pub fn new(next: Option<String>) -> Self {
        Self { next }
    }

    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let qs = serde_urlencoded::to_string(self)?;
        let path_and_query = PathAndQuery::try_from(format!("/login?{}", qs))?;
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    fn redirect(self) -> Result<impl Reply, Rejection> {
        let uri: Uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(
                self.next
                    .map(warp::http::uri::PathAndQuery::try_from)
                    .transpose()
                    .wrap_error()?
                    .unwrap_or_else(|| PathAndQuery::from_static("/")),
            );
            parts
        })
        .wrap_error()?;
        Ok(warp::redirect::see_other(uri))
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let get = warp::get()
        .and(with_templates(templates))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(warp::query())
        .and(with_optional_session(pool, cookies_config))
        .and_then(get)
        .untuple_one()
        .with(wrap_fn(save_csrf_token(cookies_config)));

    let post = warp::post()
        .and(with_connection(pool))
        .and(protected_form(cookies_config))
        .and(warp::query())
        .and_then(post)
        .untuple_one()
        .with(wrap_fn(save_session(cookies_config)));

    warp::path("login").and(get.or(post))
}

async fn get(
    templates: Templates,
    csrf_token: CsrfToken,
    query: LoginRequest,
    maybe_session: Option<SessionInfo>,
) -> Result<(CsrfToken, Box<dyn Reply>), Rejection> {
    if maybe_session.is_some() {
        Ok((csrf_token, Box::new(query.redirect()?)))
    } else {
        let ctx = ().with_csrf(&csrf_token);
        let content = templates.render_login(&ctx)?;
        Ok((csrf_token, Box::new(html(content))))
    }
}

async fn post(
    mut conn: PoolConnection<Postgres>,
    form: LoginForm,
    query: LoginRequest,
) -> Result<(SessionInfo, impl Reply), Rejection> {
    let session_info = login(&mut conn, &form.username, &form.password)
        .await
        .wrap_error()?;

    Ok((session_info, query.redirect()?))
}
