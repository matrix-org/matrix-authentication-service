// Copyright 2021 The Matrix.org Foundation C.I.C.
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
use mas_config::{CookiesConfig, CsrfConfig};
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{authenticate_session, count_active_sessions, set_password},
    PostgresqlBackend,
};
use mas_templates::{AccountContext, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::{pool::PoolConnection, PgExecutor, PgPool, Postgres, Transaction};
use warp::{reply::html, Filter, Rejection, Reply};

use crate::{
    errors::WrapError,
    filters::{
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::{connection, transaction},
        session::session,
        with_templates, CsrfToken,
    },
};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    let get = with_templates(templates)
        .and(encrypted_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(session(pool, cookies_config))
        .and(connection(pool))
        .and_then(get)
        .with(warp::filters::trace::trace(|_info| {
            tracing::info_span!("GET /account")
        }));

    let post = with_templates(templates)
        .and(encrypted_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(session(pool, cookies_config))
        .and(transaction(pool))
        .and(protected_form(cookies_config))
        .and_then(post)
        .with(warp::filters::trace::trace(|_info| {
            tracing::info_span!("POST /account")
        }));

    let filter = warp::get().and(get).or(warp::post().and(post));

    warp::path!("account").and(filter)
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
    let active_sessions = count_active_sessions(executor, &session.user)
        .await
        .wrap_error()?;
    let ctx = AccountContext::new(active_sessions)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account(&ctx).await?;
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

    let reply = render(templates, cookie_saver, csrf_token, session, &mut txn).await?;

    txn.commit().await.wrap_error()?;

    Ok(reply)
}
