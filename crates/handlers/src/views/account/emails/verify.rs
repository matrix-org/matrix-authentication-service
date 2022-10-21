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
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::user::{
    consume_email_verification, lookup_user_email_by_id, lookup_user_email_verification_code,
    mark_user_email_as_verified, set_user_email_as_primary,
};
use mas_templates::{EmailVerificationPageContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;
use ulid::Ulid;

use crate::views::shared::OptionalPostAuthAction;

#[derive(Deserialize, Debug)]
pub struct CodeForm {
    code: String,
}

pub(crate) async fn get(
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let user_email = lookup_user_email_by_id(&mut conn, &session.user, id).await?;

    if user_email.confirmed_at.is_some() {
        // This email was already verified, skip
        let destination = query.go_next_or_default(&mas_router::AccountEmails);
        return Ok((cookie_jar, destination).into_response());
    }

    let ctx = EmailVerificationPageContext::new(user_email)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_verify_email(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

pub(crate) async fn post(
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Query(query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<CodeForm>>,
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

    let email = lookup_user_email_by_id(&mut txn, &session.user, id).await?;

    if session.user.primary_email.is_none() {
        set_user_email_as_primary(&mut txn, &email).await?;
    }

    // TODO: make those 8 hours configurable
    let verification = lookup_user_email_verification_code(&mut txn, email, &form.code).await?;

    // TODO: display nice errors if the code was already consumed or expired
    let verification = consume_email_verification(&mut txn, verification).await?;

    let _email = mark_user_email_as_verified(&mut txn, verification.email).await?;

    txn.commit().await?;

    let destination = query.go_next_or_default(&mas_router::AccountEmails);
    Ok((cookie_jar, destination).into_response())
}
