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

use anyhow::Context;
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
use mas_storage::{user::UserEmailRepository, BoxClock, BoxRng, Repository};
use mas_storage_pg::PgRepository;
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
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut repo = PgRepository::from_pool(&pool).await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let user_email = repo
        .user_email()
        .lookup(id)
        .await?
        .filter(|u| u.user_id == session.user.id)
        .context("Could not find user email")?;

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
    clock: BoxClock,
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Query(query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<CodeForm>>,
) -> Result<Response, FancyError> {
    let mut repo = PgRepository::from_pool(&pool).await?;

    let form = cookie_jar.verify_form(&clock, form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let user_email = repo
        .user_email()
        .lookup(id)
        .await?
        .filter(|u| u.user_id == session.user.id)
        .context("Could not find user email")?;

    let verification = repo
        .user_email()
        .find_verification_code(&clock, &user_email, &form.code)
        .await?
        .context("Invalid code")?;

    // TODO: display nice errors if the code was already consumed or expired
    repo.user_email()
        .consume_verification_code(&clock, verification)
        .await?;

    if session.user.primary_user_email_id.is_none() {
        repo.user_email().set_as_primary(&user_email).await?;
    }

    repo.user_email()
        .mark_as_verified(&clock, user_email)
        .await?;

    repo.save().await?;

    let destination = query.go_next_or_default(&mas_router::AccountEmails);
    Ok((cookie_jar, destination).into_response())
}
