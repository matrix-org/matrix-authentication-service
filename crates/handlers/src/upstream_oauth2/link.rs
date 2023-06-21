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
use mas_data_model::UpstreamOAuthProviderImportPreference;
use mas_jose::jwt::Jwt;
use mas_keystore::Encrypter;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository},
    user::{BrowserSessionRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{
    EmptyContext, TemplateContext, Templates, UpstreamExistingLinkContext, UpstreamRegister,
    UpstreamSuggestLink,
};
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use super::UpstreamSessionsCookie;
use crate::{impl_from_error_for_route, views::shared::OptionalPostAuthAction};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    /// Couldn't find the session on the link
    #[error("Session not found")]
    SessionNotFound,

    /// Couldn't find the user
    #[error("User not found")]
    UserNotFound,

    /// Couldn't find upstream provider
    #[error("Upstream provider not found")]
    ProviderNotFound,

    /// Required claim was missing in id_token
    #[error("Required claim {0:?} missing from the upstream provider's response")]
    RequiredClaimMissing(&'static str),

    /// Session was already consumed
    #[error("Session already consumed")]
    SessionConsumed,

    #[error("Missing session cookie")]
    MissingCookie,

    #[error("Invalid form action")]
    InvalidFormAction,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_axum_utils::csrf::CsrfError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_jose::jwt::JwtDecodeError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::LinkNotFound => (StatusCode::NOT_FOUND, "Link not found").into_response(),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

#[derive(Deserialize, Default)]
struct StandardClaims {
    name: Option<String>,
    email: Option<String>,
    preferred_username: Option<String>,
}

/// Utility function to import a claim from the upstream provider's response,
/// based on the preference for that attribute.
///
/// # Parameters
///
/// * `name` - The name of the claim, for error reporting
/// * `value` - The value of the claim, if present
/// * `preference` - The preference for this claim
/// * `run` - A function to run if the claim is present. The first argument is
///   the value of the claim, and the second is whether the claim is forced to
///   be used.
///
/// # Errors
///
/// Returns an error if the claim is required but missing.
fn import_claim(
    name: &'static str,
    value: Option<String>,
    preference: &UpstreamOAuthProviderImportPreference,
    mut run: impl FnMut(String, bool) -> (),
) -> Result<(), RouteError> {
    // If this claim is ignored, we don't need to do anything.
    if preference.ignore() {
        return Ok(());
    }

    // If this claim is required and missing, we can't continue.
    if value.is_none() && preference.is_required() {
        return Err(RouteError::RequiredClaimMissing(name));
    }

    if let Some(value) = value {
        run(value, preference.is_forced());
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub(crate) enum FormData {
    Register { username: String },
    Link,
    Login,
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.link.get",
    fields(upstream_oauth_link.id = %link_id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(link_id): Path<Ulid>,
) -> Result<impl IntoResponse, RouteError> {
    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, _post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::MissingCookie)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::LinkNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    // This checks that we're in a browser session which is allowed to consume this
    // link: the upstream auth session should have been started in this browser.
    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::SessionNotFound);
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::SessionConsumed);
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, mut cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let maybe_user_session = user_session_info.load_session(&mut repo).await?;

    let render = match (maybe_user_session, link.user_id) {
        (Some(session), Some(user_id)) if session.user.id == user_id => {
            // Session already linked, and link matches the currently logged
            // user. Mark the session as consumed and renew the authentication.
            repo.upstream_oauth_session()
                .consume(&clock, upstream_session)
                .await?;

            let session = repo
                .browser_session()
                .authenticate_with_upstream(&mut rng, &clock, session, &link)
                .await?;

            cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

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
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::UserNotFound)?;

            let ctx = UpstreamExistingLinkContext::new(user)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_link_mismatch(&ctx).await?
        }

        (Some(user_session), None) => {
            // Session not linked, but user logged in: suggest linking account
            let ctx = UpstreamSuggestLink::new(&link)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_suggest_link(&ctx).await?
        }

        (None, Some(user_id)) => {
            // Session linked, but user not logged in: do the login
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::UserNotFound)?;

            let ctx = UpstreamExistingLinkContext::new(user).with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_do_login(&ctx).await?
        }

        (None, None) => {
            // Session not linked and used not logged in: suggest creating an
            // account or logging in an existing user
            let id_token = upstream_session
                .id_token()
                .map(Jwt::<'_, StandardClaims>::try_from)
                .transpose()?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound)?;

            let payload = id_token
                .map(|id_token| id_token.into_parts().1)
                .unwrap_or_default();

            let mut ctx = UpstreamRegister::new(&link);

            import_claim(
                "name",
                payload.name,
                &provider.claims_imports.displayname,
                |value, force| {
                    ctx.set_display_name(value, force);
                },
            )?;

            import_claim(
                "email",
                payload.email,
                &provider.claims_imports.email,
                |value, force| {
                    ctx.set_email(value, force);
                },
            )?;

            import_claim(
                "username",
                payload.preferred_username,
                &provider.claims_imports.localpart,
                |value, force| {
                    ctx.set_localpart(value, force);
                },
            )?;

            let ctx = ctx.with_csrf(csrf_token.form_value());

            templates.render_upstream_oauth2_do_register(&ctx).await?
        }
    };

    Ok((cookie_jar, Html(render)))
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.link.post",
    fields(upstream_oauth_link.id = %link_id),
    skip_all,
    err,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(link_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<FormData>>,
) -> Result<impl IntoResponse, RouteError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::MissingCookie)?;

    let post_auth_action = OptionalPostAuthAction {
        post_auth_action: post_auth_action.cloned(),
    };

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::LinkNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    // This checks that we're in a browser session which is allowed to consume this
    // link: the upstream auth session should have been started in this browser.
    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::SessionNotFound);
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::SessionConsumed);
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_session(&mut repo).await?;

    let session = match (maybe_user_session, link.user_id, form) {
        (Some(session), None, FormData::Link) => {
            repo.upstream_oauth_link()
                .associate_to_user(&link, &session.user)
                .await?;

            session
        }

        (None, Some(user_id), FormData::Login) => {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::UserNotFound)?;

            repo.browser_session().add(&mut rng, &clock, &user).await?
        }

        (None, None, FormData::Register { username }) => {
            let user = repo.user().add(&mut rng, &clock, username).await?;

            repo.job()
                .schedule_job(ProvisionUserJob::new(&user))
                .await?;

            repo.upstream_oauth_link()
                .associate_to_user(&link, &user)
                .await?;

            repo.browser_session().add(&mut rng, &clock, &user).await?
        }

        _ => return Err(RouteError::InvalidFormAction),
    };

    repo.upstream_oauth_session()
        .consume(&clock, upstream_session)
        .await?;

    let session = repo
        .browser_session()
        .authenticate_with_upstream(&mut rng, &clock, session, &link)
        .await?;

    let cookie_jar = sessions_cookie
        .consume_link(link_id)?
        .save(cookie_jar, &clock);
    let cookie_jar = cookie_jar.set_session(&session);

    repo.save().await?;

    Ok((cookie_jar, post_auth_action.go_next()))
}
