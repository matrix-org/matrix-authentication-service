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
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use chrono::Duration;
use lettre::{message::Mailbox, Address};
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{BrowserSession, User, UserEmail};
use mas_email::Mailer;
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::{
    user::{
        add_user_email, add_user_email_verification_code, get_user_email, get_user_emails,
        remove_user_email, set_user_email_as_primary,
    },
    Clock, PostgresqlBackend,
};
use mas_templates::{AccountEmailsContext, EmailVerificationContext, TemplateContext, Templates};
use rand::{distributions::Uniform, Rng};
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};
use tracing::info;

pub mod add;
pub mod verify;

#[derive(Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ManagementForm {
    Add { email: String },
    ResendConfirmation { data: String },
    SetPrimary { data: String },
    Remove { data: String },
}

pub(crate) async fn get(
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (clock, mut rng) = crate::rng_and_clock()?;

    let mut conn = pool.acquire().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    if let Some(session) = maybe_session {
        render(&mut rng, &clock, templates, session, cookie_jar, &mut conn).await
    } else {
        let login = mas_router::Login::default();
        Ok((cookie_jar, login.go()).into_response())
    }
}

async fn render(
    rng: impl Rng + Send,
    clock: &Clock,
    templates: Templates,
    session: BrowserSession<PostgresqlBackend>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    executor: impl PgExecutor<'_>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock.now(), rng);

    let emails = get_user_emails(executor, &session.user).await?;

    let ctx = AccountEmailsContext::new(emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_emails(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

async fn start_email_verification(
    mailer: &Mailer,
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: &User<PostgresqlBackend>,
    user_email: UserEmail<PostgresqlBackend>,
) -> anyhow::Result<()> {
    // First, generate a code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range).to_string();

    let address: Address = user_email.email.parse()?;

    let verification = add_user_email_verification_code(
        executor,
        &mut rng,
        clock,
        user_email,
        Duration::hours(8),
        code,
    )
    .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context = EmailVerificationContext::new(user.clone().into(), verification.clone().into());

    mailer.send_verification_email(mailbox, &context).await?;

    info!(
        email.id = %verification.email.data,
        "Verification email sent"
    );
    Ok(())
}

pub(crate) async fn post(
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    State(mailer): State<Mailer>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ManagementForm>>,
) -> Result<Response, FancyError> {
    let (clock, mut rng) = crate::rng_and_clock()?;
    let mut txn = pool.begin().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let mut session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let form = cookie_jar.verify_form(clock.now(), form)?;

    match form {
        ManagementForm::Add { email } => {
            let user_email =
                add_user_email(&mut txn, &mut rng, &clock, &session.user, email).await?;
            let next = mas_router::AccountVerifyEmail::new(user_email.data);
            start_email_verification(
                &mailer,
                &mut txn,
                &mut rng,
                &clock,
                &session.user,
                user_email,
            )
            .await?;
            txn.commit().await?;
            return Ok((cookie_jar, next.go()).into_response());
        }
        ManagementForm::ResendConfirmation { data } => {
            let id = data.parse()?;

            let user_email = get_user_email(&mut txn, &session.user, id).await?;
            let next = mas_router::AccountVerifyEmail::new(user_email.data);
            start_email_verification(
                &mailer,
                &mut txn,
                &mut rng,
                &clock,
                &session.user,
                user_email,
            )
            .await?;
            txn.commit().await?;
            return Ok((cookie_jar, next.go()).into_response());
        }
        ManagementForm::Remove { data } => {
            let id = data.parse()?;

            let email = get_user_email(&mut txn, &session.user, id).await?;
            remove_user_email(&mut txn, email).await?;
        }
        ManagementForm::SetPrimary { data } => {
            let id = data.parse()?;
            let email = get_user_email(&mut txn, &session.user, id).await?;
            set_user_email_as_primary(&mut txn, &email).await?;
            session.user.primary_email = Some(email);
        }
    };

    let reply = render(
        &mut rng,
        &clock,
        templates.clone(),
        session,
        cookie_jar,
        &mut txn,
    )
    .await?;

    txn.commit().await?;

    Ok(reply)
}
