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

#![allow(clippy::trait_duplication_in_bounds)]

use std::{str::FromStr, sync::Arc};

use argon2::Argon2;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use chrono::Duration;
use lettre::{message::Mailbox, Address};
use mas_axum_utils::{
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_email::Mailer;
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::Route;
use mas_storage::user::{
    add_user_email, add_user_email_verification_code, register_user, start_session, username_exists,
};
use mas_templates::{
    EmailVerificationContext, FieldError, FormError, RegisterContext, RegisterFormField,
    TemplateContext, Templates, ToFormState,
};
use rand::{distributions::Uniform, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};

use super::shared::OptionalPostAuthAction;

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

pub(crate) async fn get(
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (clock, mut rng) = crate::clock_and_rng();
    let mut conn = pool.acquire().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock.now(), &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    if maybe_session.is_some() {
        let reply = query.go_next();
        Ok((cookie_jar, reply).into_response())
    } else {
        let content = render(
            RegisterContext::default(),
            query,
            csrf_token,
            &mut conn,
            &templates,
        )
        .await?;

        Ok((cookie_jar, Html(content)).into_response())
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    State(mailer): State<Mailer>,
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, FancyError> {
    let (clock, mut rng) = crate::clock_and_rng();
    let mut txn = pool.begin().await?;

    let form = cookie_jar.verify_form(clock.now(), form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock.now(), &mut rng);

    // Validate the form
    let state = {
        let mut state = form.to_form_state();

        if form.username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if username_exists(&mut txn, &form.username).await? {
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
            &mut txn,
            &templates,
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let pfh = Argon2::default();
    let user = register_user(
        &mut txn,
        &mut rng,
        &clock,
        pfh,
        &form.username,
        &form.password,
    )
    .await?;

    let user_email = add_user_email(&mut txn, &mut rng, &clock, &user, form.email).await?;

    // First, generate a code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");

    let address: Address = user_email.email.parse()?;

    let verification = add_user_email_verification_code(
        &mut txn,
        &mut rng,
        &clock,
        user_email,
        Duration::hours(8),
        code,
    )
    .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context = EmailVerificationContext::new(user.clone(), verification.clone());

    mailer.send_verification_email(mailbox, &context).await?;

    let next = mas_router::AccountVerifyEmail::new(verification.email.id)
        .and_maybe(query.post_auth_action);

    let session = start_session(&mut txn, &mut rng, &clock, user).await?;

    txn.commit().await?;

    let cookie_jar = cookie_jar.set_session(&session);
    Ok((cookie_jar, next.go()).into_response())
}

async fn render(
    ctx: RegisterContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    conn: &mut PgConnection,
    templates: &Templates,
) -> Result<String, FancyError> {
    let next = action.load_context(conn).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value());

    let content = templates.render_register(&ctx).await?;
    Ok(content)
}
