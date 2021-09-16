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
use warp::{reply::html, Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    errors::{WrapError, WrapFormError},
    filters::{
        cookies::{with_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::with_connection,
        session::{with_optional_session, SessionCookie},
        with_templates, CsrfToken,
    },
    storage::{login, SessionInfo},
    templates::{LoginContext, LoginFormField, TemplateContext, Templates},
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
        .and(with_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(warp::query())
        .and(with_optional_session(pool, cookies_config))
        .and_then(get);

    let post = warp::post()
        .and(with_templates(templates))
        .and(with_connection(pool))
        .and(with_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(protected_form(cookies_config))
        .and(warp::query())
        .and_then(post);

    warp::path!("login").and(get.or(post))
}

async fn get(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    query: LoginRequest,
    maybe_session: Option<SessionInfo>,
) -> Result<Box<dyn Reply>, Rejection> {
    if maybe_session.is_some() {
        Ok(Box::new(query.redirect()?))
    } else {
        let ctx = LoginContext::default().with_csrf(&csrf_token);
        let content = templates.render_login(&ctx)?;
        let reply = html(content);
        let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
        Ok(Box::new(reply))
    }
}

async fn post(
    templates: Templates,
    mut conn: PoolConnection<Postgres>,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    form: LoginForm,
    query: LoginRequest,
) -> Result<Box<dyn Reply>, Rejection> {
    use crate::storage::user::LoginError;
    // TODO: recover
    match login(&mut conn, &form.username, form.password).await {
        Ok(session_info) => {
            let session_cookie = SessionCookie::from_session_info(&session_info);
            let reply = query.redirect()?;
            let reply = cookie_saver.save_encrypted(&session_cookie, reply)?;
            Ok(Box::new(reply))
        }
        Err(e) => {
            let errored_form = match e {
                LoginError::NotFound { .. } => e.on_field(LoginFormField::Username),
                LoginError::Authentication { .. } => e.on_field(LoginFormField::Password),
                LoginError::Other(_) => e.on_form(),
            };
            let ctx = LoginContext::with_form_error(errored_form).with_csrf(&csrf_token);
            let content = templates.render_login(&ctx)?;
            let reply = html(content);
            let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
            Ok(Box::new(reply))
        }
    }
}
