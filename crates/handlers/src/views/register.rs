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
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_router::Route;
use mas_storage::user::{register_user, start_session};
use mas_templates::{RegisterContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

use super::shared::OptionalPostAuthAction;

#[derive(Deserialize)]
pub(crate) struct RegisterForm {
    username: String,
    password: String,
    password_confirm: String,
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    if maybe_session.is_some() {
        let reply = query.go_next();
        Ok((cookie_jar, reply).into_response())
    } else {
        let ctx = RegisterContext::default();
        let next = query.load_context(&mut conn).await?;
        let ctx = if let Some(next) = next {
            ctx.with_post_action(next)
        } else {
            ctx
        };
        let login_link = mas_router::Login::from(query.post_auth_action).relative_url();
        let ctx = ctx.with_login_link(login_link.to_string());
        let ctx = ctx.with_csrf(csrf_token.form_value());

        let content = templates.render_register(&ctx).await?;

        Ok((cookie_jar, Html(content)).into_response())
    }
}

pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, FancyError> {
    // TODO: display nice form errors
    let mut txn = pool.begin().await?;

    let form = cookie_jar.verify_form(form)?;

    if form.password != form.password_confirm {
        return Err(anyhow::anyhow!("password mismatch").into());
    }

    let pfh = Argon2::default();
    let user = register_user(&mut txn, pfh, &form.username, &form.password).await?;

    let session = start_session(&mut txn, user).await?;

    txn.commit().await?;

    let cookie_jar = cookie_jar.set_session(&session);
    let reply = query.go_next();
    Ok((cookie_jar, reply).into_response())
}
