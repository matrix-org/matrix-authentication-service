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

use std::str::FromStr;

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::typed_header::TypedHeader;
use lettre::Address;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{SiteConfig, UserAgent};
use mas_router::UrlBuilder;
use mas_storage::{
    job::{JobRepositoryExt, SendAccountRecoveryEmailsJob},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{
    EmptyContext, FieldError, FormState, RecoveryStartContext, RecoveryStartFormField,
    TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::{BoundActivityTracker, PreferredLanguage};

#[derive(Deserialize, Serialize)]
pub(crate) struct StartRecoveryForm {
    email: String,
}

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let context = RecoveryStartContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_start(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    user_agent: TypedHeader<headers::UserAgent>,
    activity_tracker: BoundActivityTracker,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<StartRecoveryForm>>,
) -> Result<impl IntoResponse, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let user_agent = UserAgent::parse(user_agent.as_str().to_owned());
    let ip_address = activity_tracker.ip();

    let form = cookie_jar.verify_form(&clock, form)?;
    let mut form_state = FormState::from_form(&form);

    if Address::from_str(&form.email).is_err() {
        form_state =
            form_state.with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid);
    }

    if !form_state.is_valid() {
        repo.save().await?;
        let context = RecoveryStartContext::new()
            .with_form_state(form_state)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let rendered = templates.render_recovery_start(&context)?;

        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let session = repo
        .user_recovery()
        .add_session(
            &mut rng,
            &clock,
            form.email,
            user_agent,
            ip_address,
            locale.to_string(),
        )
        .await?;

    repo.job()
        .schedule_job(SendAccountRecoveryEmailsJob::new(&session))
        .await?;

    repo.save().await?;

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::AccountRecoveryProgress::new(session.id)),
    )
        .into_response())
}
