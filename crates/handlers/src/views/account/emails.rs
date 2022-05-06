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
    extract::{Extension, Form},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use lettre::{message::Mailbox, Address};
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    fancy_error, FancyError, SessionInfoExt, UrlBuilder,
};
use mas_config::Encrypter;
use mas_data_model::{BrowserSession, User, UserEmail};
use mas_email::Mailer;
use mas_storage::{
    user::{
        add_user_email, add_user_email_verification_code, get_user_email, get_user_emails,
        remove_user_email, set_user_email_as_primary,
    },
    PostgresqlBackend,
};
use mas_templates::{AccountEmailsContext, EmailVerificationContext, TemplateContext, Templates};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};
use tracing::info;

use crate::views::LoginRequest;

#[derive(Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ManagementForm {
    Add { email: String },
    ResendConfirmation { data: String },
    SetPrimary { data: String },
    Remove { data: String },
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(fancy_error(templates.clone()))?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut conn)
        .await
        .map_err(fancy_error(templates.clone()))?;

    if let Some(session) = maybe_session {
        render(templates, session, cookie_jar, &mut conn).await
    } else {
        let login = LoginRequest::default();
        Ok((cookie_jar, login.go()).into_response())
    }
}

async fn render(
    templates: Templates,
    session: BrowserSession<PostgresqlBackend>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    executor: impl PgExecutor<'_>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();

    let emails = get_user_emails(executor, &session.user)
        .await
        .map_err(fancy_error(templates.clone()))?;

    let ctx = AccountEmailsContext::new(emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates
        .render_account_emails(&ctx)
        .await
        .map_err(fancy_error(templates))?;

    Ok((cookie_jar, Html(content)).into_response())
}

async fn start_email_verification(
    mailer: &Mailer,
    url_builder: &UrlBuilder,
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    user_email: &UserEmail<PostgresqlBackend>,
) -> anyhow::Result<()> {
    // First, generate a code
    let code: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    add_user_email_verification_code(executor, user_email, &code).await?;

    // And send the verification email
    let address: Address = user_email.email.parse()?;

    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let link = url_builder.email_verification(&code);

    let context = EmailVerificationContext::new(user.clone().into(), link);

    mailer.send_verification_email(mailbox, &context).await?;

    info!(email.id = user_email.data, "Verification email sent");
    Ok(())
}

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Extension(url_builder): Extension<UrlBuilder>,
    Extension(mailer): Extension<Mailer>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ManagementForm>>,
) -> Result<Response, FancyError> {
    let mut txn = pool.begin().await.map_err(fancy_error(templates.clone()))?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut txn)
        .await
        .map_err(fancy_error(templates.clone()))?;

    let mut session = if let Some(session) = maybe_session {
        session
    } else {
        let login = LoginRequest::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let form = cookie_jar
        .verify_form(form)
        .map_err(fancy_error(templates.clone()))?;

    match form {
        ManagementForm::Add { email } => {
            let user_email = add_user_email(&mut txn, &session.user, email)
                .await
                .map_err(fancy_error(templates.clone()))?;
            start_email_verification(&mailer, &url_builder, &mut txn, &session.user, &user_email)
                .await
                .map_err(fancy_error(templates.clone()))?;
        }
        ManagementForm::Remove { data } => {
            let id = data.parse().map_err(fancy_error(templates.clone()))?;

            let email = get_user_email(&mut txn, &session.user, id)
                .await
                .map_err(fancy_error(templates.clone()))?;
            remove_user_email(&mut txn, email)
                .await
                .map_err(fancy_error(templates.clone()))?;
        }
        ManagementForm::ResendConfirmation { data } => {
            let id = data.parse().map_err(fancy_error(templates.clone()))?;

            let user_email = get_user_email(&mut txn, &session.user, id)
                .await
                .map_err(fancy_error(templates.clone()))?;

            start_email_verification(&mailer, &url_builder, &mut txn, &session.user, &user_email)
                .await
                .map_err(fancy_error(templates.clone()))?;
        }
        ManagementForm::SetPrimary { data } => {
            let id = data.parse().map_err(fancy_error(templates.clone()))?;
            let email = get_user_email(&mut txn, &session.user, id)
                .await
                .map_err(fancy_error(templates.clone()))?;
            set_user_email_as_primary(&mut txn, &email)
                .await
                .map_err(fancy_error(templates.clone()))?;
            session.user.primary_email = Some(email);
        }
    };

    let reply = render(templates.clone(), session, cookie_jar, &mut txn).await?;

    txn.commit().await.map_err(fancy_error(templates.clone()))?;

    Ok(reply)
}
