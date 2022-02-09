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

#![allow(clippy::trait_duplication_in_bounds)]

use argon2::Argon2;
use hyper::http::uri::{Parts, PathAndQuery, Uri};
use mas_config::{CsrfConfig, Encrypter};
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{register_user, start_session},
    PostgresqlBackend,
};
use mas_templates::{RegisterContext, TemplateContext, Templates};
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        self,
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::{connection, transaction},
        session::{optional_session, SessionCookie},
        with_templates, CsrfToken,
    },
};
use serde::Deserialize;
use sqlx::{pool::PoolConnection, PgPool, Postgres, Transaction};
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

use super::{LoginRequest, PostAuthAction};

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

impl From<PostAuthAction> for RegisterRequest {
    fn from(post_auth_action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(post_auth_action),
        }
    }
}

impl RegisterRequest {
    #[allow(dead_code)]
    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let path_and_query = if let Some(next) = &self.post_auth_action {
            let qs = serde_urlencoded::to_string(next)?;
            PathAndQuery::try_from(format!("/register?{}", qs))?
        } else {
            PathAndQuery::from_static("/register")
        };
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    fn redirect(self) -> Result<impl Reply, Rejection> {
        let uri = self
            .post_auth_action
            .as_ref()
            .map(PostAuthAction::build_uri)
            .transpose()
            .wrap_error()?
            .unwrap_or_else(|| Uri::from_static("/"));
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
    encrypter: &Encrypter,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let get = warp::get()
        .and(filters::trace::name("GET /register"))
        .and(with_templates(templates))
        .and(connection(pool))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(warp::query())
        .and(optional_session(pool, encrypter))
        .and_then(get);

    let post = warp::post()
        .and(filters::trace::name("POST /register"))
        .and(transaction(pool))
        .and(encrypted_cookie_saver(encrypter))
        .and(protected_form(encrypter))
        .and(warp::query())
        .and_then(post);

    warp::path!("register").and(get.or(post).unify()).boxed()
}

async fn get(
    templates: Templates,
    mut conn: PoolConnection<Postgres>,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    query: RegisterRequest,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
) -> Result<Box<dyn Reply>, Rejection> {
    if maybe_session.is_some() {
        Ok(Box::new(query.redirect()?))
    } else {
        let ctx = RegisterContext::default();
        let ctx = match query.post_auth_action {
            Some(next) => {
                let login_link = LoginRequest::from(next.clone()).build_uri().wrap_error()?;
                let next = next.load_context(&mut conn).await.wrap_error()?;
                ctx.with_post_action(next)
                    .with_login_link(login_link.to_string())
            }
            None => ctx,
        };
        let ctx = ctx.with_csrf(csrf_token.form_value());
        let content = templates.render_register(&ctx).await?;
        let reply = html(content);
        let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
        Ok(Box::new(reply))
    }
}

async fn post(
    mut txn: Transaction<'_, Postgres>,
    cookie_saver: EncryptedCookieSaver,
    form: RegisterForm,
    query: RegisterRequest,
) -> Result<Box<dyn Reply>, Rejection> {
    // TODO: display nice form errors
    if form.password != form.password_confirm {
        return Err(anyhow::anyhow!("password mismatch")).wrap_error();
    }

    let pfh = Argon2::default();
    let user = register_user(&mut txn, pfh, &form.username, &form.password)
        .await
        .wrap_error()?;

    let session_info = start_session(&mut txn, user).await.wrap_error()?;

    txn.commit().await.wrap_error()?;

    let session_cookie = SessionCookie::from_session(&session_info);
    let reply = query.redirect()?;
    let reply = cookie_saver.save_encrypted(&session_cookie, reply)?;
    Ok(Box::new(reply))
}
