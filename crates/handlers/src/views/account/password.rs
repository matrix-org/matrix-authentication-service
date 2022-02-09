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

use argon2::Argon2;
use mas_config::{CsrfConfig, Encrypter};
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{authenticate_session, set_password},
    PostgresqlBackend,
};
use mas_templates::{EmptyContext, TemplateContext, Templates};
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        self,
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::transaction,
        session::session,
        with_templates, CsrfToken,
    },
};
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    encrypter: &Encrypter,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let get = with_templates(templates)
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(session(pool, encrypter))
        .and_then(get);

    let post = with_templates(templates)
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(session(pool, encrypter))
        .and(transaction(pool))
        .and(protected_form(encrypter))
        .and_then(post);

    let get = warp::get()
        .and(get)
        .and(filters::trace::name("GET /account/passwords"));
    let post = warp::post()
        .and(post)
        .and(filters::trace::name("POST /account/passwords"));
    let filter = get.or(post).unify();

    warp::path!("password").and(filter).boxed()
}

#[derive(Deserialize)]
struct Form {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

async fn get(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
) -> Result<Box<dyn Reply>, Rejection> {
    render(templates, cookie_saver, csrf_token, session).await
}

async fn render(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
) -> Result<Box<dyn Reply>, Rejection> {
    let ctx = EmptyContext
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_password(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;

    Ok(Box::new(reply))
}

async fn post(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    mut session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
    form: Form,
) -> Result<Box<dyn Reply>, Rejection> {
    authenticate_session(&mut txn, &mut session, form.current_password)
        .await
        .wrap_error()?;

    // TODO: display nice form errors
    if form.new_password != form.new_password_confirm {
        return Err(anyhow::anyhow!("password mismatch")).wrap_error();
    }

    let phf = Argon2::default();
    set_password(&mut txn, phf, &session.user, &form.new_password)
        .await
        .wrap_error()?;

    let reply = render(templates, cookie_saver, csrf_token, session).await?;

    txn.commit().await.wrap_error()?;

    Ok(reply)
}
