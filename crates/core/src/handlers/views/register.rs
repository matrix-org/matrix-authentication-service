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

use argon2::Argon2;
use hyper::http::uri::{Parts, PathAndQuery, Uri};
use mas_data_model::BrowserSession;
use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{reply::html, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::WrapError,
    filters::{
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::connection,
        session::{optional_session, SessionCookie},
        with_templates, CsrfToken,
    },
    storage::{register_user, user::start_session, PostgresqlBackend},
    templates::{EmptyContext, TemplateContext, Templates},
};

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    next: Option<String>,
}

impl RegisterRequest {
    #[allow(dead_code)]
    pub fn new(next: Option<String>) -> Self {
        Self { next }
    }

    #[allow(dead_code)]
    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let qs = serde_urlencoded::to_string(self)?;
        let path_and_query = PathAndQuery::try_from(format!("/register?{}", qs))?;
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
struct RegisterForm {
    username: String,
    password: String,
    password_confirm: String,
}

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let get = warp::get()
        .and(with_templates(templates))
        .and(encrypted_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(warp::query())
        .and(optional_session(pool, cookies_config))
        .and_then(get);

    let post = warp::post()
        .and(connection(pool))
        .and(encrypted_cookie_saver(cookies_config))
        .and(protected_form(cookies_config))
        .and(warp::query())
        .and_then(post);

    warp::path!("register").and(get.or(post))
}

async fn get(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    query: RegisterRequest,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
) -> Result<Box<dyn Reply>, Rejection> {
    if maybe_session.is_some() {
        Ok(Box::new(query.redirect()?))
    } else {
        let ctx = EmptyContext.with_csrf(&csrf_token);
        let content = templates.render_register(&ctx)?;
        let reply = html(content);
        let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
        Ok(Box::new(reply))
    }
}

async fn post(
    mut conn: PoolConnection<Postgres>,
    cookie_saver: EncryptedCookieSaver,
    form: RegisterForm,
    query: RegisterRequest,
) -> Result<impl Reply, Rejection> {
    if form.password != form.password_confirm {
        return Err(anyhow::anyhow!("password mismatch")).wrap_error();
    }

    let pfh = Argon2::default();
    let user = register_user(&mut conn, pfh, &form.username, &form.password)
        .await
        .wrap_error()?;

    let session_info = start_session(&mut conn, user).await.wrap_error()?;

    let session_cookie = SessionCookie::from_session(&session_info);
    let reply = query.redirect()?;
    let reply = cookie_saver.save_encrypted(&session_cookie, reply)?;
    Ok(reply)
}
