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

use mas_config::{CsrfConfig, Encrypter, HttpConfig};
use mas_data_model::BrowserSession;
use mas_storage::PostgresqlBackend;
use mas_templates::{IndexContext, TemplateContext, Templates};
use mas_warp_utils::filters::{
    self,
    cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
    csrf::updated_csrf_token,
    session::optional_session,
    url_builder::{url_builder, UrlBuilder},
    with_templates, CsrfToken,
};
use sqlx::PgPool;
use warp::{filters::BoxedFilter, reply::html, Filter, Rejection, Reply};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    encrypter: &Encrypter,
    http_config: &HttpConfig,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    warp::path::end()
        .and(filters::trace::name("GET /"))
        .and(warp::get())
        .and(url_builder(http_config))
        .and(with_templates(templates))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(optional_session(pool, encrypter))
        .and_then(get)
        .boxed()
}

async fn get(
    url_builder: UrlBuilder,
    templates: Templates,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    maybe_session: Option<BrowserSession<PostgresqlBackend>>,
) -> Result<Box<dyn Reply>, Rejection> {
    let ctx = IndexContext::new(url_builder.oidc_discovery())
        .maybe_with_session(maybe_session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_index(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
    Ok(Box::new(reply))
}
