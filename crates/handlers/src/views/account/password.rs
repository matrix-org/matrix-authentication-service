// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use argon2::Argon2;
use axum::{
    extract::{Extension, Form},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_data_model::BrowserSession;
use mas_router::Route;
use mas_storage::{
    user::{authenticate_session, set_password},
    PostgresqlBackend,
};
use mas_templates::{EmptyContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Deserialize)]
pub struct ChangeForm {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    if let Some(session) = maybe_session {
        render(templates, session, cookie_jar).await
    } else {
        let login = mas_router::Login::default();
        Ok((cookie_jar, login.go()).into_response())
    }
}

async fn render(
    templates: Templates,
    session: BrowserSession<PostgresqlBackend>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();

    let ctx = EmptyContext
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_password(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ChangeForm>>,
) -> Result<Response, FancyError> {
    let mut txn = pool.begin().await?;

    let form = cookie_jar.verify_form(form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let mut session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    authenticate_session(&mut txn, &mut session, &form.current_password).await?;

    // TODO: display nice form errors
    if form.new_password != form.new_password_confirm {
        return Err(anyhow::anyhow!("password mismatch").into());
    }

    let phf = Argon2::default();
    set_password(&mut txn, phf, &session.user, &form.new_password).await?;

    let reply = render(templates.clone(), session, cookie_jar).await?;

    txn.commit().await?;

    Ok(reply)
}
