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

use lettre::{message::Mailbox, Address};
use mas_config::{CsrfConfig, Encrypter, HttpConfig};
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
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        self,
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::{connection, transaction},
        session::session,
        url_builder::{url_builder, UrlBuilder},
        with_templates, CsrfToken,
    },
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use sqlx::{pool::PoolConnection, PgExecutor, PgPool, Postgres, Transaction};
use tracing::info;
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    mailer: &Mailer,
    encrypter: &Encrypter,
    http_config: &HttpConfig,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let mailer = mailer.clone();

    let get = with_templates(templates)
        .and(filters::trace::name("GET /account/emails"))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(session(pool, encrypter))
        .and(connection(pool))
        .and_then(get);

    let post = with_templates(templates)
        .and(filters::trace::name("POST /account/emails"))
        .and(warp::any().map(move || mailer.clone()))
        .and(url_builder(http_config))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(session(pool, encrypter))
        .and(transaction(pool))
        .and(protected_form(encrypter))
        .and_then(post);

    let get = warp::get().and(get);
    let post = warp::post().and(post);
    let filter = get.or(post).unify();

    warp::path!("emails").and(filter).boxed()
}

#[derive(Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Form {
    Add { email: String },
    ResendConfirmation { data: String },
    SetPrimary { data: String },
    Remove { data: String },
}

async fn get(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
    mut conn: PoolConnection<Postgres>,
) -> Result<Box<dyn Reply>, Rejection> {
    render(templates, cookie_saver, csrf_token, session, &mut conn).await
}

async fn render(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
    executor: impl PgExecutor<'_>,
) -> Result<Box<dyn Reply>, Rejection> {
    let emails = get_user_emails(executor, &session.user)
        .await
        .wrap_error()?;

    let ctx = AccountEmailsContext::new(emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_emails(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;

    Ok(Box::new(reply))
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

#[allow(clippy::too_many_arguments)]
async fn post(
    templates: Templates,
    mailer: Mailer,
    url_builder: UrlBuilder,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    mut session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
    form: Form,
) -> Result<Box<dyn Reply>, Rejection> {
    match form {
        Form::Add { email } => {
            let user_email = add_user_email(&mut txn, &session.user, email)
                .await
                .wrap_error()?;
            start_email_verification(&mailer, &url_builder, &mut txn, &session.user, &user_email)
                .await
                .wrap_error()?;
        }
        Form::Remove { data } => {
            let id = data.parse().wrap_error()?;
            let email = get_user_email(&mut txn, &session.user, id)
                .await
                .wrap_error()?;
            remove_user_email(&mut txn, email).await.wrap_error()?;
        }
        Form::ResendConfirmation { data } => {
            let id: i64 = data.parse().wrap_error()?;

            let user_email = get_user_email(&mut txn, &session.user, id)
                .await
                .wrap_error()?;

            start_email_verification(&mailer, &url_builder, &mut txn, &session.user, &user_email)
                .await
                .wrap_error()?;
        }
        Form::SetPrimary { data } => {
            let id = data.parse().wrap_error()?;
            let email = get_user_email(&mut txn, &session.user, id)
                .await
                .wrap_error()?;
            set_user_email_as_primary(&mut txn, &email)
                .await
                .wrap_error()?;
            session.user.primary_email = Some(email);
        }
    };

    let reply = render(templates, cookie_saver, csrf_token, session, &mut txn).await?;

    txn.commit().await.wrap_error()?;

    Ok(reply)
}
