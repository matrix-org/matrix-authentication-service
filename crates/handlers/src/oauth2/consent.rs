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

use std::sync::Arc;

use anyhow::Context;
use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    SessionInfoExt,
};
use mas_data_model::AuthorizationGrantStage;
use mas_keystore::Encrypter;
use mas_policy::PolicyFactory;
use mas_router::{PostAuthAction, Route};
use mas_storage::oauth2::{
    authorization_grant::{get_grant_by_id, give_consent_to_grant},
    consent::insert_client_consent,
};
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

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
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(templates): State<Templates>,
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<Ulid>,
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

        let mut policy = policy_factory.instantiate().await?;
        let res = policy
            .evaluate_authorization_grant(&grant, &session.user)
            .await?;

        if res.valid() {
            let ctx = ConsentContext::new(grant, PostAuthAction::continue_grant(grant_id))
                .with_session(session)
                .with_csrf(csrf_token.form_value());

            let content = templates
                .render_consent(&ctx)
                .await
                .context("failed to render template")?;

            Ok((cookie_jar, Html(content)).into_response())
        } else {
            let ctx = PolicyViolationContext::new(grant, PostAuthAction::continue_grant(grant_id))
                .with_session(session)
                .with_csrf(csrf_token.form_value());

            let content = templates
                .render_policy_violation(&ctx)
                .await
                .context("failed to render template")?;

            Ok((cookie_jar, Html(content)).into_response())
        }
    } else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        Ok((cookie_jar, login.go()).into_response())
    }
}

pub(crate) async fn post(
    State(policy_factory): State<Arc<PolicyFactory>>,
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(grant_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, RouteError> {
    let (clock, mut rng) = crate::rng_and_clock()?;
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

    let mut policy = policy_factory.instantiate().await?;
    let res = policy
        .evaluate_authorization_grant(&grant, &session.user)
        .await?;

    if !res.valid() {
        return Err(anyhow::anyhow!("policy violation").into());
    }

    // Do not consent for the "urn:matrix:org.matrix.msc2967.client:device:*" scope
    let scope_without_device = grant
        .scope
        .iter()
        .filter(|s| !s.starts_with("urn:matrix:org.matrix.msc2967.client:device:"))
        .cloned()
        .collect();
    insert_client_consent(
        &mut txn,
        &mut rng,
        &clock,
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
