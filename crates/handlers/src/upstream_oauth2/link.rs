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
    csrf::{CsrfError, CsrfExt, ProtectedForm},
    SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_storage::{
    upstream_oauth2::{lookup_link, lookup_session_on_link},
    user::{lookup_user, ActiveSessionLookupError, UserLookupError},
    GenericLookupError, LookupResultExt,
};
use mas_templates::{
    EmptyContext, TemplateContext, TemplateError, Templates, UpstreamExistingLinkContext,
};
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    /// Couldn't find the session on the link
    #[error("Session not found")]
    SessionNotFound,

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

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<TemplateError> for RouteError {
    fn from(e: TemplateError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<ActiveSessionLookupError> for RouteError {
    fn from(e: ActiveSessionLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<CsrfError> for RouteError {
    fn from(e: CsrfError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<UserLookupError> for RouteError {
    fn from(e: UserLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<GenericLookupError> for RouteError {
    fn from(e: GenericLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

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
    let _upstream_session = lookup_session_on_link(&mut txn, &link, session_id)
        .await
        .to_option()?
        .ok_or(RouteError::SessionNotFound)?;

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock.now(), &mut rng);
    let maybe_user_session = user_session_info.load_session(&mut txn).await?;

    let render = match (maybe_user_session, maybe_user_id) {
        (Some(user_session), Some(user_id)) if user_session.user.data == user_id => {
            // Session already linked, and link matches the currently logged
            // user. Do nothing?
            let ctx = EmptyContext
                .with_session(user_session)
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
    let (clock, _rng) = crate::rng_and_clock()?;
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
    let _upstream_session = lookup_session_on_link(&mut txn, &link, session_id)
        .await
        .to_option()?
        .ok_or(RouteError::SessionNotFound)?;

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_session(&mut txn).await?;

    let res = match (maybe_user_session, maybe_user_id, form) {
        (Some(_user_session), None, FormData::Link) => "Linked!".to_owned(),

        (None, Some(_user_id), FormData::Login) => "Logged in!".to_owned(),

        (None, None, FormData::Register { username }) => format!("Registered {username}!"),

        _ => return Err(RouteError::InvalidFormAction),
    };

    Ok((cookie_jar, res))
}
