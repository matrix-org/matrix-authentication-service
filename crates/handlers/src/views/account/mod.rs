// Copyright 2021-2022 The Matrix.org Foundation C.I.C.
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

mod emails;
mod password;

use mas_config::{CookiesConfig, CsrfConfig};
use mas_data_model::BrowserSession;
use mas_email::Mailer;
use mas_storage::{
    user::{count_active_sessions, get_user_emails},
    PostgresqlBackend,
};
use mas_templates::{AccountContext, TemplateContext, Templates};
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::updated_csrf_token,
        database::connection,
        session::session,
        with_templates, CsrfToken,
    },
};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

use self::{emails::filter as emails, password::filter as password};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    mailer: &Mailer,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let get = warp::get()
        .and(with_templates(templates))
        .and(encrypted_cookie_saver(cookies_config))
        .and(updated_csrf_token(cookies_config, csrf_config))
        .and(session(pool, cookies_config))
        .and(connection(pool))
        .and_then(get);

    let index = warp::path::end().and(get);
    let password = password(pool, templates, csrf_config, cookies_config);
    let emails = emails(pool, templates, mailer, csrf_config, cookies_config);

    let filter = index.or(password).unify().or(emails).unify();

    warp::path::path("account").and(filter).boxed()
}

async fn get(
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
    mut conn: PoolConnection<Postgres>,
) -> Result<Box<dyn Reply>, Rejection> {
    let active_sessions = count_active_sessions(&mut conn, &session.user)
        .await
        .wrap_error()?;

    let emails = get_user_emails(&mut conn, &session.user)
        .await
        .wrap_error()?;

    let ctx = AccountContext::new(active_sessions, emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_index(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;

    Ok(Box::new(reply))
}
