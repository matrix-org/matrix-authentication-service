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

use axum::{
    extract::{Extension, Form, Query},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_email::Mailer;
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::user::add_user_email;
use mas_templates::{EmailAddContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

use super::start_email_verification;
use crate::views::shared::OptionalPostAuthAction;

#[derive(Deserialize, Debug)]
pub struct EmailForm {
    email: String,
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.begin().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let ctx = EmailAddContext::new()
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_add_email(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Extension(mailer): Extension<Mailer>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Query(query): Query<OptionalPostAuthAction>,
    Form(form): Form<ProtectedForm<EmailForm>>,
) -> Result<Response, FancyError> {
    let mut txn = pool.begin().await?;

    let form = cookie_jar.verify_form(form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let user_email = add_user_email(&mut txn, &session.user, &form.email).await?;
    let next = mas_router::AccountVerifyEmail::new(user_email.data);
    let next = if let Some(action) = query.post_auth_action {
        next.and_then(action)
    } else {
        next
    };
    start_email_verification(&mailer, &mut txn, &session.user, user_email).await?;

    txn.commit().await?;

    Ok((cookie_jar, next.go()).into_response())
}
