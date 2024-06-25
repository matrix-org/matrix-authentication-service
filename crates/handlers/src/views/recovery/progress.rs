// Copyright 2024 The Matrix.org Foundation C.I.C.
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
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_router::UrlBuilder;
use mas_storage::{
    job::{JobRepositoryExt, SendAccountRecoveryEmailsJob},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{RecoveryProgressContext, TemplateContext, Templates};
use ulid::Ulid;

use crate::PreferredLanguage;

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::AccountRecoveryStart),
        )
            .into_response());
    };

    let context = RecoveryProgressContext::new(recovery_session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_progress(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::AccountRecoveryStart),
        )
            .into_response());
    };

    // Verify the CSRF token
    let () = cookie_jar.verify_form(&clock, form)?;

    // Schedule a new batch of emails
    repo.job()
        .schedule_job(SendAccountRecoveryEmailsJob::new(&recovery_session))
        .await?;

    repo.save().await?;

    let context = RecoveryProgressContext::new(recovery_session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_progress(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}
