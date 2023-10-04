// Copyright 2022 The Matrix.org Foundation C.I.C.
//
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

use std::collections::HashMap;

use anyhow::Context;
use axum::{
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::Duration;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::Device;
use mas_router::{CompatLoginSsoAction, PostAuthAction, Route};
use mas_storage::{
    compat::{CompatSessionRepository, CompatSsoLoginRepository},
    job::{JobRepositoryExt, ProvisionDeviceJob},
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
};
use mas_templates::{CompatSsoContext, ErrorContext, TemplateContext, Templates};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::PreferredLanguage;

#[derive(Serialize)]
struct AllParams<'s> {
    #[serde(flatten)]
    existing_params: HashMap<&'s str, &'s str>,

    #[serde(rename = "loginToken")]
    login_token: &'s str,
}

#[derive(Debug, Deserialize)]
pub struct Params {
    action: Option<CompatLoginSsoAction>,
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.get",
    fields(compat_sso_login.id = %id),
    skip_all,
    err,
)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Query(params): Query<Params>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                mas_router::Register::and_continue_compat_sso_login(id).go()
            }
            Some(CompatLoginSsoAction::Login) | None => {
                mas_router::Login::and_continue_compat_sso_login(id).go()
            }
        };

        return Ok((cookie_jar, url).into_response());
    };

    // TODO: make that more generic, check that the email has been confirmed
    if session.user.primary_user_email_id.is_none() {
        let destination = mas_router::AccountAddEmail::default()
            .and_then(PostAuthAction::continue_compat_sso_login(id));
        return Ok((cookie_jar, destination.go()).into_response());
    }

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")?;

    // Bail out if that login session is more than 30min old
    if clock.now() > login.created_at + Duration::minutes(30) {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned());

        let content = templates.render_error(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    let ctx = CompatSsoContext::new(login)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_sso_login(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.post",
    fields(compat_sso_login.id = %id),
    skip_all,
    err,
)]
pub async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Query(params): Query<Params>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    cookie_jar.verify_form(&clock, form)?;

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                mas_router::Register::and_continue_compat_sso_login(id).go()
            }
            Some(CompatLoginSsoAction::Login) | None => {
                mas_router::Login::and_continue_compat_sso_login(id).go()
            }
        };

        return Ok((cookie_jar, url).into_response());
    };

    // TODO: make that more generic
    if session.user.primary_user_email_id.is_none() {
        let destination = mas_router::AccountAddEmail::default()
            .and_then(PostAuthAction::continue_compat_sso_login(id));
        return Ok((cookie_jar, destination.go()).into_response());
    }

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")?;

    // Bail out if that login session is more than 30min old
    if clock.now() > login.created_at + Duration::minutes(30) {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned());

        let content = templates.render_error(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    let redirect_uri = {
        let mut redirect_uri = login.redirect_uri.clone();
        let existing_params = redirect_uri
            .query()
            .map(serde_urlencoded::from_str)
            .transpose()?
            .unwrap_or_default();

        let params = AllParams {
            existing_params,
            login_token: &login.login_token,
        };
        let query = serde_urlencoded::to_string(params)?;
        redirect_uri.set_query(Some(&query));
        redirect_uri
    };

    let device = Device::generate(&mut rng);
    repo.job()
        .schedule_job(ProvisionDeviceJob::new(&session.user, &device))
        .await?;

    let compat_session = repo
        .compat_session()
        .add(&mut rng, &clock, &session.user, device, false)
        .await?;

    repo.compat_sso_login()
        .fulfill(&clock, login, &compat_session)
        .await?;

    repo.save().await?;

    Ok((cookie_jar, Redirect::to(redirect_uri.as_str())).into_response())
}
