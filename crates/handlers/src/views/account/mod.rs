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

pub mod emails;
pub mod password;

use axum::{
    extract::Extension,
    response::{Html, IntoResponse, Redirect, Response},
};
use mas_axum_utils::{csrf::CsrfExt, fancy_error, FancyError, PrivateCookieJar, SessionInfoExt};
use mas_config::Encrypter;
use mas_storage::user::{count_active_sessions, get_user_emails};
use mas_templates::{AccountContext, TemplateContext, Templates};
use sqlx::PgPool;

use super::LoginRequest;

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
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

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = LoginRequest::default();
        let login = login.build_uri().map_err(fancy_error(templates.clone()))?;
        return Ok((cookie_jar.headers(), Redirect::to(login)).into_response());
    };

    let active_sessions = count_active_sessions(&mut conn, &session.user)
        .await
        .map_err(fancy_error(templates.clone()))?;

    let emails = get_user_emails(&mut conn, &session.user)
        .await
        .map_err(fancy_error(templates.clone()))?;

    let ctx = AccountContext::new(active_sessions, emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates
        .render_account_index(&ctx)
        .await
        .map_err(fancy_error(templates.clone()))?;

    Ok((cookie_jar.headers(), Html(content)).into_response())
}
