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

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::user::authenticate_session;
use mas_templates::{ReauthContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

use super::shared::OptionalPostAuthAction;

#[derive(Deserialize, Debug)]
pub(crate) struct ReauthForm {
    password: String,
}

pub(crate) async fn get(
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, login.go()).into_response());
    };

    let ctx = ReauthContext::default();
    let next = query.load_context(&mut conn).await?;
    let ctx = if let Some(next) = next {
        // SAFETY: we should have an action only if we have a "next" context
        // TODO: make that cleaner
        let action = query.post_auth_action.unwrap();
        ctx.with_post_action(next, action)
    } else {
        ctx
    };
    let ctx = ctx.with_session(session).with_csrf(csrf_token.form_value());

    let content = templates.render_reauth(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

pub(crate) async fn post(
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ReauthForm>>,
) -> Result<Response, FancyError> {
    let mut txn = pool.begin().await?;

    let form = cookie_jar.verify_form(form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let mut session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, login.go()).into_response());
    };

    // TODO: recover from errors here
    authenticate_session(&mut txn, &mut session, &form.password).await?;
    let cookie_jar = cookie_jar.set_session(&session);
    txn.commit().await?;

    let reply = query.go_next();
    Ok((cookie_jar, reply).into_response())
}
