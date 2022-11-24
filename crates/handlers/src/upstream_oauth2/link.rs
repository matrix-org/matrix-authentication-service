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

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse},
    Form,
};
use axum_extra::extract::PrivateCookieJar;
use hyper::StatusCode;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::{
    upstream_oauth2::{
        associate_link_to_user, consume_session, lookup_link, lookup_session_on_link,
    },
    user::{
        authenticate_session_with_upstream, lookup_user, register_passwordless_user, start_session,
    },
    LookupResultExt,
};
use mas_templates::{EmptyContext, TemplateContext, Templates, UpstreamExistingLinkContext};
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    /// Couldn't find the session on the link
    #[error("Session not found")]
    SessionNotFound,

    /// Session was already consumed
    #[error("Session already consumed")]
    SessionConsumed,

    #[error("Missing session cookie")]
    MissingCookie,

    #[error("Invalid session cookie")]
    InvalidCookie(#[source] ulid::DecodeError),

    #[error("Invalid form action")]
    InvalidFormAction,

    #[error(transparent)]
    InternalError(Box<dyn std::error::Error>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl_from_error_for_route!(sqlx::Error);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::GenericLookupError);
impl_from_error_for_route!(mas_storage::user::ActiveSessionLookupError);
impl_from_error_for_route!(mas_storage::user::UserLookupError);
impl_from_error_for_route!(mas_axum_utils::csrf::CsrfError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::LinkNotFound => (StatusCode::NOT_FOUND, "Link not found").into_response(),
            Self::InternalError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            Self::Anyhow(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response()
            }
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub(crate) enum FormData {
    Register { username: String },
    Link,
    Login,
}

pub(crate) async fn get(
    State(pool): State<PgPool>,
    State(templates): State<Templates>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(link_id): Path<Ulid>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;
    let (clock, mut rng) = crate::rng_and_clock()?;

    let (link, _provider_id, maybe_user_id) = lookup_link(&mut txn, link_id)
        .await
        .to_option()?
        .ok_or(RouteError::LinkNotFound)?;

    // XXX: that cookie should be managed elsewhere
    let cookie = cookie_jar
        .get("upstream-oauth2-session-id")
        .ok_or(RouteError::MissingCookie)?;

    let session_id: Ulid = cookie.value().parse().map_err(RouteError::InvalidCookie)?;

    // This checks that we're in a browser session which is allowed to consume this
    // link: the upstream auth session should have been started in this browser.
    let upstream_session = lookup_session_on_link(&mut txn, &link, session_id)
        .await
        .to_option()?
        .ok_or(RouteError::SessionNotFound)?;

    if upstream_session.consumed() {
        return Err(RouteError::SessionConsumed);
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, mut cookie_jar) = cookie_jar.csrf_token(clock.now(), &mut rng);
    let maybe_user_session = user_session_info.load_session(&mut txn).await?;

    let render = match (maybe_user_session, maybe_user_id) {
        (Some(mut session), Some(user_id)) if session.user.data == user_id => {
            // Session already linked, and link matches the currently logged
            // user. Mark the session as consumed and renew the authentication.
            consume_session(&mut txn, &clock, upstream_session).await?;
            authenticate_session_with_upstream(&mut txn, &mut rng, &clock, &mut session, &link)
                .await?;

            cookie_jar = cookie_jar.set_session(&session);

            txn.commit().await?;

            let ctx = EmptyContext
                .with_session(session)
                .with_csrf(csrf_token.form_value());

            templates
                .render_upstream_oauth2_already_linked(&ctx)
                .await?
        }

        (Some(user_session), Some(user_id)) => {
            // Session already linked, but link doesn't match the currently
            // logged user. Suggest logging out of the current user
            // and logging in with the new one
            let user = lookup_user(&mut txn, user_id).await?;

            let ctx = UpstreamExistingLinkContext::new(user)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_link_mismatch(&ctx).await?
        }

        (Some(user_session), None) => {
            // Session not linked, but user logged in: suggest linking account
            let ctx = EmptyContext
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_suggest_link(&ctx).await?
        }

        (None, Some(user_id)) => {
            // Session linked, but user not logged in: do the login
            let user = lookup_user(&mut txn, user_id).await?;

            let ctx = UpstreamExistingLinkContext::new(user).with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_do_login(&ctx).await?
        }

        (None, None) => {
            // Session not linked and used not logged in: suggest creating an
            // account or logging in an existing user
            let ctx = EmptyContext.with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_do_register(&ctx).await?
        }
    };

    Ok((cookie_jar, Html(render)))
}

pub(crate) async fn post(
    State(pool): State<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(link_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<FormData>>,
) -> Result<impl IntoResponse, RouteError> {
    let mut txn = pool.begin().await?;
    let (clock, mut rng) = crate::rng_and_clock()?;
    let form = cookie_jar.verify_form(clock.now(), form)?;

    let (link, _provider_id, maybe_user_id) = lookup_link(&mut txn, link_id)
        .await
        .to_option()?
        .ok_or(RouteError::LinkNotFound)?;

    // XXX: that cookie should be managed elsewhere
    let cookie = cookie_jar
        .get("upstream-oauth2-session-id")
        .ok_or(RouteError::MissingCookie)?;

    let session_id: Ulid = cookie.value().parse().map_err(RouteError::InvalidCookie)?;

    // This checks that we're in a browser session which is allowed to consume this
    // link: the upstream auth session should have been started in this browser.
    let upstream_session = lookup_session_on_link(&mut txn, &link, session_id)
        .await
        .to_option()?
        .ok_or(RouteError::SessionNotFound)?;

    if upstream_session.consumed() {
        return Err(RouteError::SessionConsumed);
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_session(&mut txn).await?;

    let mut session = match (maybe_user_session, maybe_user_id, form) {
        (Some(session), None, FormData::Link) => {
            associate_link_to_user(&mut txn, &link, &session.user).await?;
            session
        }

        (None, Some(user_id), FormData::Login) => {
            let user = lookup_user(&mut txn, user_id).await?;
            start_session(&mut txn, &mut rng, &clock, user).await?
        }

        (None, None, FormData::Register { username }) => {
            let user = register_passwordless_user(&mut txn, &mut rng, &clock, &username).await?;
            associate_link_to_user(&mut txn, &link, &user).await?;

            start_session(&mut txn, &mut rng, &clock, user).await?
        }

        _ => return Err(RouteError::InvalidFormAction),
    };

    consume_session(&mut txn, &clock, upstream_session).await?;
    authenticate_session_with_upstream(&mut txn, &mut rng, &clock, &mut session, &link).await?;

    let cookie_jar = cookie_jar.set_session(&session);

    txn.commit().await?;

    Ok((cookie_jar, mas_router::Index.go()))
}
