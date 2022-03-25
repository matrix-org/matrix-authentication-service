// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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
use axum::{
    extract::{Extension, Form, Query},
    response::{Html, IntoResponse, Redirect, Response},
};
use hyper::http::uri::{Parts, PathAndQuery, Uri};
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    fancy_error, FancyError, PrivateCookieJar, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_storage::user::{register_user, start_session};
use mas_templates::{RegisterContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

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

    fn redirect(self) -> Result<impl IntoResponse, anyhow::Error> {
        let uri = if let Some(action) = self.post_auth_action {
            action.build_uri()?
        } else {
            Uri::from_static("/")
        };

        Ok(Redirect::to(uri))
    }
}

#[derive(Deserialize)]
pub(crate) struct RegisterForm {
    username: String,
    password: String,
    password_confirm: String,
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<RegisterRequest>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(fancy_error(templates.clone()))?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut conn)
        .await
        .map_err(fancy_error(templates.clone()))?;

    if maybe_session.is_some() {
        let response = query
            .redirect()
            .map_err(fancy_error(templates.clone()))?
            .into_response();
        Ok(response)
    } else {
        let ctx = RegisterContext::default();
        let ctx = match &query.post_auth_action {
            Some(next) => {
                let next = next
                    .load_context(&mut conn)
                    .await
                    .map_err(fancy_error(templates.clone()))?;
                ctx.with_post_action(next)
            }
            None => ctx,
        };
        let login_link = LoginRequest::from(query.post_auth_action)
            .build_uri()
            .map_err(fancy_error(templates.clone()))?;
        let ctx = ctx.with_login_link(login_link.to_string());
        let ctx = ctx.with_csrf(csrf_token.form_value());

        let content = templates
            .render_register(&ctx)
            .await
            .map_err(fancy_error(templates.clone()))?;

        Ok((cookie_jar.headers(), Html(content)).into_response())
    }
}

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<RegisterRequest>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, FancyError> {
    // TODO: display nice form errors
    let mut txn = pool.begin().await.map_err(fancy_error(templates.clone()))?;

    let form = cookie_jar
        .verify_form(form)
        .map_err(fancy_error(templates.clone()))?;

    if form.password != form.password_confirm {
        return Err(anyhow::anyhow!("password mismatch")).map_err(fancy_error(templates.clone()));
    }

    let pfh = Argon2::default();
    let user = register_user(&mut txn, pfh, &form.username, &form.password)
        .await
        .map_err(fancy_error(templates.clone()))?;

    let session = start_session(&mut txn, user)
        .await
        .map_err(fancy_error(templates.clone()))?;

    txn.commit().await.map_err(fancy_error(templates.clone()))?;

    let cookie_jar = cookie_jar.set_session(&session);
    let reply = query.redirect().map_err(fancy_error(templates.clone()))?;
    Ok((cookie_jar.headers(), reply).into_response())
}
