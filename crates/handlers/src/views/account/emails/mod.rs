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

use anyhow::{anyhow, Context};
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
use mas_storage::{user::UserEmailRepository, BoxClock, BoxRepository, BoxRng, Clock, Repository};
use mas_templates::{AccountEmailsContext, EmailVerificationContext, TemplateContext, Templates};
use rand::{distributions::Uniform, Rng};
use serde::Deserialize;
use tracing::info;

pub mod add;
pub mod verify;

#[derive(Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ManagementForm {
    Add { email: String },
    ResendConfirmation { id: String },
    SetPrimary { id: String },
    Remove { id: String },
}

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut *repo).await?;

    if let Some(session) = maybe_session {
        render(&mut rng, &clock, templates, session, cookie_jar, &mut *repo).await
    } else {
        let login = mas_router::Login::default();
        Ok((cookie_jar, login.go()).into_response())
    }
}

async fn render<E: std::error::Error>(
    rng: impl Rng + Send,
    clock: &impl Clock,
    templates: Templates,
    session: BrowserSession,
    cookie_jar: PrivateCookieJar<Encrypter>,
    repo: &mut (impl Repository<Error = E> + ?Sized),
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);

    let emails = repo.user_email().all(&session.user).await?;

    let ctx = AccountEmailsContext::new(emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_emails(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

async fn start_email_verification<E: std::error::Error + Send + Sync + 'static>(
    mailer: &Mailer,
    repo: &mut (impl Repository<Error = E> + ?Sized),
    mut rng: impl Rng + Send,
    clock: &impl Clock,
    user: &User,
    user_email: UserEmail,
) -> anyhow::Result<()> {
    // First, generate a code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range).to_string();

    let address: Address = user_email.email.parse()?;

    let verification = repo
        .user_email()
        .add_verification_code(&mut rng, clock, &user_email, Duration::hours(8), code)
        .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context = EmailVerificationContext::new(user.clone(), verification.clone());

    mailer.send_verification_email(mailbox, &context).await?;

    info!(
        email.id = %user_email.id,
        "Verification email sent"
    );
    Ok(())
}

pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    State(mailer): State<Mailer>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ManagementForm>>,
) -> Result<Response, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut *repo).await?;

    let mut session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let form = cookie_jar.verify_form(&clock, form)?;

    match form {
        ManagementForm::Add { email } => {
            let email = repo
                .user_email()
                .add(&mut rng, &clock, &session.user, email)
                .await?;

            let next = mas_router::AccountVerifyEmail::new(email.id);
            start_email_verification(&mailer, &mut *repo, &mut rng, &clock, &session.user, email)
                .await?;
            repo.save().await?;
            return Ok((cookie_jar, next.go()).into_response());
        }
        ManagementForm::ResendConfirmation { id } => {
            let id = id.parse()?;

            let email = repo
                .user_email()
                .lookup(id)
                .await?
                .context("Email not found")?;

            if email.user_id != session.user.id {
                return Err(anyhow!("Email not found").into());
            }

            let next = mas_router::AccountVerifyEmail::new(email.id);
            start_email_verification(&mailer, &mut *repo, &mut rng, &clock, &session.user, email)
                .await?;
            repo.save().await?;
            return Ok((cookie_jar, next.go()).into_response());
        }
        ManagementForm::Remove { id } => {
            let id = id.parse()?;

            let email = repo
                .user_email()
                .lookup(id)
                .await?
                .context("Email not found")?;

            if email.user_id != session.user.id {
                return Err(anyhow!("Email not found").into());
            }

            repo.user_email().remove(email).await?;
        }
        ManagementForm::SetPrimary { id } => {
            let id = id.parse()?;
            let email = repo
                .user_email()
                .lookup(id)
                .await?
                .context("Email not found")?;

            if email.user_id != session.user.id {
                return Err(anyhow!("Email not found").into());
            }

            repo.user_email().set_as_primary(&email).await?;
            session.user.primary_user_email_id = Some(email.id);
        }
    };

    let reply = render(
        &mut rng,
        &clock,
        templates.clone(),
        session,
        cookie_jar,
        &mut *repo,
    )
    .await?;

    repo.save().await?;

    Ok(reply)
}
