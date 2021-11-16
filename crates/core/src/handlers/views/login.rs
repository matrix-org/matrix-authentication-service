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
use mas_data_model::{errors::WrapFormError, BrowserSession, StorageBackend};
use mas_templates::{LoginContext, LoginFormField, TemplateContext, Templates};
use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{reply::html, Filter, Rejection, Reply};

use super::shared::PostAuthAction;
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
    storage::{login, PostgresqlBackend},
};

#[derive(Deserialize)]
#[serde(
    rename_all = "snake_case",
    bound = "<S as StorageBackend>::AuthorizationGrantData: Deserialize<'de>"
)]
pub(crate) struct LoginRequest<S: StorageBackend> {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    next: Option<PostAuthAction<S>>,
}

impl<S: StorageBackend> From<PostAuthAction<S>> for LoginRequest<S> {
    fn from(next: PostAuthAction<S>) -> Self {
        Self { next: Some(next) }
    }
}

impl<S: StorageBackend> LoginRequest<S> {
    pub fn build_uri(&self) -> anyhow::Result<Uri>
    where
        S::AuthorizationGrantData: Serialize,
    {
        let path_and_query = if let Some(next) = &self.next {
            let qs = serde_urlencoded::to_string(next)?;
            PathAndQuery::try_from(format!("/login?{}", qs))?
        } else {
            PathAndQuery::from_static("/login")
        };
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    fn redirect(self) -> Result<impl Reply, Rejection>
    where
        S::AuthorizationGrantData: Serialize,
    {
        let uri = self
            .next
            .as_ref()
            .map(PostAuthAction::build_uri)
            .transpose()
            .wrap_error()?
            .unwrap_or_else(|| Uri::from_static("/"));
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
        .and(encrypted_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(warp::query())
        .and(optional_session(pool, cookies_config))
        .and_then(get);

    let post = warp::post()
        .and(with_templates(templates))
        .and(connection(pool))
        .and(encrypted_cookie_saver(cookies_config))
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
    query: LoginRequest<PostgresqlBackend>,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
) -> Result<Box<dyn Reply>, Rejection> {
    if maybe_session.is_some() {
        Ok(Box::new(query.redirect()?))
    } else {
        let ctx = LoginContext::default().with_csrf(csrf_token.form_value());
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
    query: LoginRequest<PostgresqlBackend>,
) -> Result<Box<dyn Reply>, Rejection> {
    use crate::storage::user::LoginError;
    // TODO: recover
    match login(&mut conn, &form.username, form.password).await {
        Ok(session_info) => {
            let session_cookie = SessionCookie::from_session(&session_info);
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
            let ctx =
                LoginContext::with_form_error(errored_form).with_csrf(csrf_token.form_value());
            let content = templates.render_login(&ctx)?;
            let reply = html(content);
            let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
            Ok(Box::new(reply))
        }
    }
}
