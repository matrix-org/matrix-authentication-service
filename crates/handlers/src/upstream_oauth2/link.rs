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
    Form, TypedHeader,
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{UpstreamOAuthProviderImportPreference, User};
use mas_jose::jwt::Jwt;
use mas_policy::Policy;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository},
    user::{BrowserSessionRepository, UserEmailRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{
    ErrorContext, TemplateContext, Templates, UpstreamExistingLinkContext, UpstreamRegister,
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

    #[error("Missing username")]
    MissingUsername,

    #[error("Policy violation: {violations:?}")]
    PolicyViolation {
        violations: Vec<mas_policy::Violation>,
    },

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_axum_utils::csrf::CsrfError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_jose::jwt::JwtDecodeError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::LinkNotFound => (StatusCode::NOT_FOUND, "Link not found").into_response(),
            Self::PolicyViolation { violations } => {
                let details = violations.iter().map(|v| v.msg.clone()).collect::<Vec<_>>();
                let details = details.join("\n");
                let ctx = ErrorContext::new()
                    .with_description(
                        "Account registration denied because of policy violation".to_owned(),
                    )
                    .with_details(details);
                FancyError::new(ctx).into_response()
            }
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

#[derive(Deserialize, Default)]
struct StandardClaims {
    name: Option<String>,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
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
    mut run: impl FnMut(String, bool),
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
    Register {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        import_email: Option<String>,
        #[serde(default)]
        import_display_name: Option<String>,
    },
    Link,
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
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Path(link_id): Path<Ulid>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
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
    let (csrf_token, mut cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let maybe_user_session = user_session_info.load_session(&mut repo).await?;

    let response = match (maybe_user_session, link.user_id) {
        (Some(session), Some(user_id)) if session.user.id == user_id => {
            // Session already linked, and link matches the currently logged
            // user. Mark the session as consumed and renew the authentication.
            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

            post_auth_action.go_next().into_response()
        }

        (Some(user_session), Some(user_id)) => {
            // Session already linked, but link doesn't match the currently
            // logged user. Suggest logging out of the current user
            // and logging in with the new one
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                // XXX: is that right?
                .filter(User::is_valid)
                .ok_or(RouteError::UserNotFound)?;

            let ctx = UpstreamExistingLinkContext::new(user)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            Html(templates.render_upstream_oauth2_link_mismatch(&ctx).await?).into_response()
        }

        (Some(user_session), None) => {
            // Session not linked, but user logged in: suggest linking account
            let ctx = UpstreamSuggestLink::new(&link)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value());

            Html(templates.render_upstream_oauth2_suggest_link(&ctx).await?).into_response()
        }

        (None, Some(user_id)) => {
            // Session linked, but user not logged in: do the login
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .filter(mas_data_model::User::is_valid)
                .ok_or(RouteError::UserNotFound)?;

            let session = repo
                .browser_session()
                .add(&mut rng, &clock, &user, user_agent)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);
            cookie_jar = cookie_jar.set_session(&session);

            repo.save().await?;

            post_auth_action.go_next().into_response()
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
                "preferred_username",
                payload.preferred_username,
                &provider.claims_imports.localpart,
                |value, force| {
                    ctx.set_localpart(value, force);
                },
            )?;

            let ctx = ctx.with_csrf(csrf_token.form_value());

            Html(templates.render_upstream_oauth2_do_register(&ctx).await?).into_response()
        }
    };

    Ok((cookie_jar, response))
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
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    mut policy: Policy,
    Path(link_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<FormData>>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
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

        (
            None,
            None,
            FormData::Register {
                username,
                import_email,
                import_display_name,
            },
        ) => {
            // Those fields are Some("on") if the checkbox is checked
            let import_email = import_email.is_some();
            let import_display_name = import_display_name.is_some();

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

            // Let's try to import the claims from the ID token

            let mut name = None;
            import_claim(
                "name",
                payload.name,
                &provider.claims_imports.displayname,
                |value, force| {
                    // Import the display name if it is either forced or the user has requested it
                    if force || import_display_name {
                        name = Some(value);
                    }
                },
            )?;

            let mut email = None;
            import_claim(
                "email",
                payload.email,
                &provider.claims_imports.email,
                |value, force| {
                    // Import the email if it is either forced or the user has requested it
                    if force || import_email {
                        email = Some(value);
                    }
                },
            )?;

            let mut username = username;
            import_claim(
                "preferred_username",
                payload.preferred_username,
                &provider.claims_imports.localpart,
                |value, force| {
                    // If the username is forced, override whatever was in the form
                    if force {
                        username = Some(value);
                    }
                },
            )?;

            let username = username.ok_or(RouteError::MissingUsername)?;

            // Policy check
            let res = policy
                .evaluate_upstream_oauth_register(&username, email.as_deref())
                .await?;
            if !res.valid() {
                return Err(RouteError::PolicyViolation {
                    violations: res.violations,
                });
            }

            // Now we can create the user
            let user = repo.user().add(&mut rng, &clock, username).await?;

            // And schedule the job to provision it
            let mut job = ProvisionUserJob::new(&user);

            // If we have a display name, set it during provisioning
            if let Some(name) = name {
                job = job.set_display_name(name);
            }

            repo.job().schedule_job(job).await?;

            // If we have an email, add it to the user
            if let Some(email) = email {
                let user_email = repo
                    .user_email()
                    .add(&mut rng, &clock, &user, email)
                    .await?;

                // Mark the email as verified if the upstream provider says it is.
                if payload.email_verified {
                    repo.user_email()
                        .mark_as_verified(&clock, user_email)
                        .await?;
                }
            }

            repo.upstream_oauth_link()
                .associate_to_user(&link, &user)
                .await?;

            repo.browser_session()
                .add(&mut rng, &clock, &user, user_agent)
                .await?
        }

        _ => return Err(RouteError::InvalidFormAction),
    };

    let upstream_session = repo
        .upstream_oauth_session()
        .consume(&clock, upstream_session)
        .await?;

    repo.browser_session()
        .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
        .await?;

    let cookie_jar = sessions_cookie
        .consume_link(link_id)?
        .save(cookie_jar, &clock);
    let cookie_jar = cookie_jar.set_session(&session);

    repo.save().await?;

    Ok((cookie_jar, post_auth_action.go_next()))
}
