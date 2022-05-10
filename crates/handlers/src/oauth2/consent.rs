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

use anyhow::Context;
use axum::{
    extract::{Extension, Form, Path},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    SessionInfoExt,
};
use mas_config::Encrypter;
use mas_data_model::AuthorizationGrantStage;
use mas_router::{PostAuthAction, Route};
use mas_storage::oauth2::{
    authorization_grant::{get_grant_by_id, give_consent_to_grant},
    consent::insert_client_consent,
};
use mas_templates::{ConsentContext, TemplateContext, Templates};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<i64>,
) -> Result<Response, RouteError> {
    let mut conn = pool
        .acquire()
        .await
        .context("failed to acquire db connection")?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut conn)
        .await
        .context("could not load session")?;

    let grant = get_grant_by_id(&mut conn, grant_id).await?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(anyhow::anyhow!("authorization grant not pending").into());
    }

    if let Some(session) = maybe_session {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token();

        let ctx = ConsentContext::new(grant)
            .with_session(session)
            .with_csrf(csrf_token.form_value());

        let content = templates
            .render_consent(&ctx)
            .await
            .context("failed to render template")?;

        Ok((cookie_jar, Html(content)).into_response())
    } else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        Ok((cookie_jar, login.go()).into_response())
    }
}

pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<i64>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, RouteError> {
    let mut txn = pool
        .begin()
        .await
        .context("failed to begin db transaction")?;

    cookie_jar
        .verify_form(form)
        .context("csrf verification failed")?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut txn)
        .await
        .context("could not load session")?;

    let grant = get_grant_by_id(&mut txn, grant_id).await?;
    let next = PostAuthAction::continue_grant(grant_id);

    let session = if let Some(session) = maybe_session {
        session
    } else {
        let login = mas_router::Login::and_then(next);
        return Ok((cookie_jar, login.go()).into_response());
    };

    // Do not consent for the "urn:matrix:device:*" scope
    let scope_without_device = grant
        .scope
        .iter()
        .filter(|s| !s.starts_with("urn:matrix:device:"))
        .cloned()
        .collect();
    insert_client_consent(
        &mut txn,
        &session.user,
        &grant.client,
        &scope_without_device,
    )
    .await?;

    let _grant = give_consent_to_grant(&mut txn, grant)
        .await
        .context("failed to give consent to grant")?;

    txn.commit().await.context("could not commit txn")?;

    Ok((cookie_jar, next.go_next()).into_response())
}
