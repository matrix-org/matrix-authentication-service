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

use hyper::http::uri::{Parts, PathAndQuery};
use mas_config::{CsrfConfig, Encrypter};
use mas_data_model::BrowserSession;
use mas_storage::{user::authenticate_session, PostgresqlBackend};
use mas_templates::{ReauthContext, TemplateContext, Templates};
use mas_warp_utils::{
    errors::WrapError,
    filters::{
        self,
        cookies::{encrypted_cookie_saver, EncryptedCookieSaver},
        csrf::{protected_form, updated_csrf_token},
        database::{connection, transaction},
        session::session,
        with_templates, CsrfToken,
    },
};
use serde::Deserialize;
use sqlx::{pool::PoolConnection, PgPool, Postgres, Transaction};
use warp::{filters::BoxedFilter, hyper::Uri, reply::html, Filter, Rejection, Reply};

use super::PostAuthAction;

#[derive(Deserialize)]
pub(crate) struct ReauthRequest {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

impl From<PostAuthAction> for ReauthRequest {
    fn from(post_auth_action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(post_auth_action),
        }
    }
}

impl ReauthRequest {
    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let path_and_query = if let Some(next) = &self.post_auth_action {
            let qs = serde_urlencoded::to_string(next)?;
            PathAndQuery::try_from(format!("/reauth?{}", qs))?
        } else {
            PathAndQuery::from_static("/reauth")
        };
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    fn redirect(self) -> Result<impl Reply, Rejection> {
        let uri = self
            .post_auth_action
            .as_ref()
            .map(PostAuthAction::build_uri)
            .transpose()
            .wrap_error()?
            .unwrap_or_else(|| Uri::from_static("/"));
        Ok(warp::redirect::see_other(uri))
    }
}

#[derive(Deserialize, Debug)]
struct ReauthForm {
    password: String,
}

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    encrypter: &Encrypter,
    csrf_config: &CsrfConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let get = warp::get()
        .and(filters::trace::name("GET /reauth"))
        .and(with_templates(templates))
        .and(connection(pool))
        .and(encrypted_cookie_saver(encrypter))
        .and(updated_csrf_token(encrypter, csrf_config))
        .and(session(pool, encrypter))
        .and(warp::query())
        .and_then(get);

    let post = warp::post()
        .and(filters::trace::name("POST /reauth"))
        .and(session(pool, encrypter))
        .and(transaction(pool))
        .and(protected_form(encrypter))
        .and(warp::query())
        .and_then(post);

    warp::path!("reauth").and(get.or(post).unify()).boxed()
}

async fn get(
    templates: Templates,
    mut conn: PoolConnection<Postgres>,
    cookie_saver: EncryptedCookieSaver,
    csrf_token: CsrfToken,
    session: BrowserSession<PostgresqlBackend>,
    query: ReauthRequest,
) -> Result<Box<dyn Reply>, Rejection> {
    let ctx = ReauthContext::default();
    let ctx = match query.post_auth_action {
        Some(next) => {
            let next = next.load_context(&mut conn).await.wrap_error()?;
            ctx.with_post_action(next)
        }
        None => ctx,
    };
    let ctx = ctx.with_session(session).with_csrf(csrf_token.form_value());

    let content = templates.render_reauth(&ctx).await?;
    let reply = html(content);
    let reply = cookie_saver.save_encrypted(&csrf_token, reply)?;
    Ok(Box::new(reply))
}

async fn post(
    mut session: BrowserSession<PostgresqlBackend>,
    mut txn: Transaction<'_, Postgres>,
    form: ReauthForm,
    query: ReauthRequest,
) -> Result<Box<dyn Reply>, Rejection> {
    // TODO: recover from errors here
    authenticate_session(&mut txn, &mut session, form.password)
        .await
        .wrap_error()?;
    txn.commit().await.wrap_error()?;

    Ok(Box::new(query.redirect()?))
}
