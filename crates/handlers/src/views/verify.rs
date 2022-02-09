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

use chrono::Duration;
use mas_config::{CsrfConfig, Encrypter};
use mas_data_model::BrowserSession;
use mas_storage::{
    user::{
        consume_email_verification, lookup_user_email_verification_code,
        mark_user_email_as_verified,
    },
    PostgresqlBackend,
};
use mas_templates::{EmptyContext, TemplateContext, Templates};
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        self,
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::updated_csrf_token,
        database::transaction,
        session::optional_session,
        with_templates, CsrfToken,
    },
};
use sqlx::{PgPool, Postgres, Transaction};
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    encrypter: &Encrypter,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    warp::path!("verify" / String)
        .and(filters::trace::name("GET /verify"))
        .and(warp::get())
        .and(with_templates(templates))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(optional_session(pool, encrypter))
        .and(transaction(pool))
        .and_then(get)
        .boxed()
}

async fn get(
    code: String,
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
    mut txn: Transaction<'_, Postgres>,
) -> Result<Box<dyn Reply>, Rejection> {
    // TODO: make those 8 hours configurable
    let verification = lookup_user_email_verification_code(&mut txn, &code, Duration::hours(8))
        .await
        .wrap_error()?;

    // TODO: display nice errors if the code was already consumed or expired

    let verification = consume_email_verification(&mut txn, verification)
        .await
        .wrap_error()?;

    let _email = mark_user_email_as_verified(&mut txn, verification.email)
        .await
        .wrap_error()?;

    let ctx = EmptyContext
        .maybe_with_session(maybe_session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_email_verification_done(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;

    txn.commit().await.wrap_error()?;

    Ok(Box::new(reply))
}
