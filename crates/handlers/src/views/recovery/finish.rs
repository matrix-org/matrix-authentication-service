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

use anyhow::Context;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError,
};
use mas_data_model::SiteConfig;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng};
use mas_templates::{
    EmptyContext, ErrorContext, FieldError, FormState, RecoveryExpiredContext,
    RecoveryFinishContext, RecoveryFinishFormField, TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{passwords::PasswordManager, PreferredLanguage};

#[derive(Deserialize)]
pub(crate) struct RouteQuery {
    ticket: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RouteForm {
    new_password: String,
    new_password_confirm: String,
}

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Query(query): Query<RouteQuery>,
) -> Result<Response, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let ticket = repo
        .user_recovery()
        .find_ticket(&query.ticket)
        .await?
        .context("Unknown ticket")?;

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Unknown session")?;

    if session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    if !ticket.active(clock.now()) {
        let context = RecoveryExpiredContext::new(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let rendered = templates.render_recovery_expired(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        // Only allow confirmed email addresses
        .filter(|email| email.confirmed_at.is_some())
        .context("Unknown email address")?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Invalid user")?;

    if !user.is_valid() {
        // TODO: render a 'account locked' page
        let rendered = templates.render_error(
            &ErrorContext::new()
                .with_code("Account locked")
                .with_language(&locale),
        )?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let context = RecoveryFinishContext::new(user)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_finish(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    mut policy: Policy,
    State(site_config): State<SiteConfig>,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Query(query): Query<RouteQuery>,
    Form(form): Form<ProtectedForm<RouteForm>>,
) -> Result<Response, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let ticket = repo
        .user_recovery()
        .find_ticket(&query.ticket)
        .await?
        .context("Unknown ticket")?;

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Unknown session")?;

    if session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    if !ticket.active(clock.now()) {
        let context = RecoveryExpiredContext::new(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let rendered = templates.render_recovery_expired(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        // Only allow confirmed email addresses
        .filter(|email| email.confirmed_at.is_some())
        .context("Unknown email address")?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Invalid user")?;

    if !user.is_valid() {
        // TODO: render a 'account locked' page
        let rendered = templates.render_error(
            &ErrorContext::new()
                .with_code("Account locked")
                .with_language(&locale),
        )?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    // Check the form
    let mut form_state = FormState::from_form(&form);

    if form.new_password.is_empty() {
        form_state = form_state
            .with_error_on_field(RecoveryFinishFormField::NewPassword, FieldError::Required);
    }

    if form.new_password_confirm.is_empty() {
        form_state = form_state.with_error_on_field(
            RecoveryFinishFormField::NewPasswordConfirm,
            FieldError::Required,
        );
    }

    if form.new_password != form.new_password_confirm {
        form_state = form_state
            .with_error_on_field(
                RecoveryFinishFormField::NewPassword,
                FieldError::Unspecified,
            )
            .with_error_on_field(
                RecoveryFinishFormField::NewPasswordConfirm,
                FieldError::PasswordMismatch,
            );
    }

    let res = policy.evaluate_password(&form.new_password).await?;

    if !res.valid() {
        form_state = form_state.with_error_on_field(
            RecoveryFinishFormField::NewPassword,
            FieldError::Policy {
                message: res.to_string(),
            },
        );
    }

    if !form_state.is_valid() {
        let context = RecoveryFinishContext::new(user)
            .with_form_state(form_state)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let rendered = templates.render_recovery_finish(&context)?;

        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    // Form is valid, change the password
    let password = Zeroizing::new(form.new_password.into_bytes());
    let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;
    repo.user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    // Mark the session as consumed
    repo.user_recovery()
        .consume_ticket(&clock, ticket, session)
        .await?;

    repo.save().await?;

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::Login::default()),
    )
        .into_response())
}
