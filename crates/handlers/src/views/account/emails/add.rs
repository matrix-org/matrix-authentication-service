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
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_policy::Policy;
use mas_router::Route;
use mas_storage::{
    job::{JobRepositoryExt, VerifyEmailJob},
    user::UserEmailRepository,
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{EmailAddContext, ErrorContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{views::shared::OptionalPostAuthAction, BoundActivityTracker};

#[derive(Deserialize, Debug)]
pub struct EmailForm {
    email: String,
}

#[tracing::instrument(name = "handlers.views.account_email_add.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = EmailAddContext::new()
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_add_email(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.account_email_add.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    mut policy: Policy,
    cookie_jar: CookieJar,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    Form(form): Form<ProtectedForm<EmailForm>>,
) -> Result<Response, FancyError> {
    let form = cookie_jar.verify_form(&clock, form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    // XXX: we really should show human readable errors on the form here

    // Validate the email address
    if form.email.parse::<lettre::Address>().is_err() {
        return Err(anyhow::anyhow!("Invalid email address").into());
    }

    // Run the email policy
    let res = policy.evaluate_email(&form.email).await?;
    if !res.valid() {
        return Err(FancyError::new(
            ErrorContext::new()
                .with_description(format!("Email address {:?} denied by policy", form.email))
                .with_details(format!("{res}")),
        ));
    }

    // Find an existing email address
    let existing_user_email = repo.user_email().find(&session.user, &form.email).await?;
    let user_email = if let Some(user_email) = existing_user_email {
        user_email
    } else {
        repo.user_email()
            .add(&mut rng, &clock, &session.user, form.email)
            .await?
    };

    // If the email was not confirmed, send a confirmation email & redirect to the
    // verify page
    let next = if user_email.confirmed_at.is_none() {
        repo.job()
            .schedule_job(VerifyEmailJob::new(&user_email))
            .await?;

        let next = mas_router::AccountVerifyEmail::new(user_email.id);
        let next = if let Some(action) = query.post_auth_action {
            next.and_then(action)
        } else {
            next
        };

        next.go()
    } else {
        query.go_next_or_default(&mas_router::Account::default())
    };

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    Ok((cookie_jar, next).into_response())
}
