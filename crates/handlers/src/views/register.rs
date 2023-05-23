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

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::{
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::Route;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob, VerifyEmailJob},
    user::{BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{
    FieldError, FormError, RegisterContext, RegisterFormField, TemplateContext, Templates,
    ToFormState,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::passwords::PasswordManager;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
}

impl ToFormState for RegisterForm {
    type Field = RegisterFormField;
}

#[tracing::instrument(name = "handlers.views.register.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    State(password_manager): State<PasswordManager>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if maybe_session.is_some() {
        let reply = query.go_next();
        return Ok((cookie_jar, reply).into_response());
    }

    if !password_manager.is_enabled() {
        // If password-based login is disabled, redirect to the login page here
        return Ok(mas_router::Login::from(query.post_auth_action)
            .go()
            .into_response());
    }

    let content = render(
        RegisterContext::default(),
        query,
        csrf_token,
        &mut repo,
        &templates,
    )
    .await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.register.post", skip_all, err)]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(password_manager): State<PasswordManager>,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, FancyError> {
    if !password_manager.is_enabled() {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the form
    let state = {
        let mut state = form.to_form_state();

        if form.username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if repo.user().exists(&form.username).await? {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        }

        if form.email.is_empty() {
            state.add_error_on_field(RegisterFormField::Email, FieldError::Required);
        } else if Address::from_str(&form.email).is_err() {
            state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
        }

        if form.password.is_empty() {
            state.add_error_on_field(RegisterFormField::Password, FieldError::Required);
        }

        if form.password_confirm.is_empty() {
            state.add_error_on_field(RegisterFormField::PasswordConfirm, FieldError::Required);
        }

        if form.password != form.password_confirm {
            state.add_error_on_form(FormError::PasswordMismatch);
            state.add_error_on_field(RegisterFormField::Password, FieldError::Unspecified);
            state.add_error_on_field(RegisterFormField::PasswordConfirm, FieldError::Unspecified);
        }

        let mut policy = policy_factory.instantiate().await?;
        let res = policy
            .evaluate_register(&form.username, &form.password, &form.email)
            .await?;

        for violation in res.violations {
            match violation.field.as_deref() {
                Some("email") => state.add_error_on_field(
                    RegisterFormField::Email,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                Some("username") => state.add_error_on_field(
                    RegisterFormField::Username,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                Some("password") => state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                _ => state.add_error_on_form(FormError::Policy {
                    message: violation.msg,
                }),
            }
        }

        state
    };

    if !state.is_valid() {
        let content = render(
            RegisterContext::default().with_form_state(state),
            query,
            csrf_token,
            &mut repo,
            &templates,
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let user = repo.user().add(&mut rng, &clock, form.username).await?;
    let password = Zeroizing::new(form.password.into_bytes());
    let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;
    let user_password = repo
        .user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, form.email)
        .await?;

    let next = mas_router::AccountVerifyEmail::new(user_email.id).and_maybe(query.post_auth_action);

    let session = repo.browser_session().add(&mut rng, &clock, &user).await?;

    let session = repo
        .browser_session()
        .authenticate_with_password(&mut rng, &clock, session, &user_password)
        .await?;

    repo.job()
        .schedule_job(VerifyEmailJob::new(&user_email))
        .await?;

    repo.job()
        .schedule_job(ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    let cookie_jar = cookie_jar.set_session(&session);
    Ok((cookie_jar, next.go()).into_response())
}

async fn render(
    ctx: RegisterContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
) -> Result<String, FancyError> {
    let next = action.load_context(repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value());

    let content = templates.render_register(&ctx).await?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use hyper::{header::LOCATION, Request, StatusCode};
    use mas_router::Route;
    use sqlx::PgPool;

    use crate::{
        passwords::PasswordManager,
        test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        init_tracing();
        let state = {
            let mut state = TestState::from_pool(pool).await.unwrap();
            state.password_manager = PasswordManager::disabled();
            state
        };

        let request = Request::get(&*mas_router::Register::default().relative_url()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let request = Request::post(&*mas_router::Register::default().relative_url()).form(
            serde_json::json!({
                "csrf": "abc",
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }
}
