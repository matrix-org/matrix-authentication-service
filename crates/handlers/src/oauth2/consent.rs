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
use mas_storage::{
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
    Clock, Repository,
};
use mas_storage_pg::PgRepository;
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] mas_axum_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant already used")]
    GrantNotPending,

    #[error("Policy violation")]
    PolicyViolation,

    #[error("Failed to load client")]
    NoSuchClient,
}

impl_from_error_for_route!(sqlx::Error);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage_pg::DatabaseError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::InstanciateError);
impl_from_error_for_route!(mas_policy::EvaluationError);

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
    let (clock, mut rng) = crate::clock_and_rng();
    let mut repo = PgRepository::from_pool(&pool).await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending);
    }

    if let Some(session) = maybe_session {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock.now(), &mut rng);

        let mut policy = policy_factory.instantiate().await?;
        let res = policy
            .evaluate_authorization_grant(&grant, &session.user)
            .await?;

        if res.valid() {
            let ctx = ConsentContext::new(grant)
                .with_session(session)
                .with_csrf(csrf_token.form_value());

            let content = templates.render_consent(&ctx).await?;

            Ok((cookie_jar, Html(content)).into_response())
        } else {
            let ctx = PolicyViolationContext::new(grant)
                .with_session(session)
                .with_csrf(csrf_token.form_value());

            let content = templates.render_policy_violation(&ctx).await?;

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
    let (clock, mut rng) = crate::clock_and_rng();
    let mut repo = PgRepository::from_pool(&pool).await?;

    cookie_jar.verify_form(clock.now(), form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;
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
        return Err(RouteError::PolicyViolation);
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient)?;

    // Do not consent for the "urn:matrix:org.matrix.msc2967.client:device:*" scope
    let scope_without_device = grant
        .scope
        .iter()
        .filter(|s| !s.starts_with("urn:matrix:org.matrix.msc2967.client:device:"))
        .cloned()
        .collect();
    repo.oauth2_client()
        .give_consent_for_user(
            &mut rng,
            &clock,
            &client,
            &session.user,
            &scope_without_device,
        )
        .await?;

    repo.oauth2_authorization_grant()
        .give_consent(grant)
        .await?;

    repo.save().await?;

    Ok((cookie_jar, next.go_next()).into_response())
}
