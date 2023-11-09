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
    response::{Html, IntoResponse, Response},
    Form, TypedHeader,
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    sentry::SentryEventID,
    FancyError, SessionInfoExt,
};
use mas_data_model::{UpstreamOAuthProviderImportAction, User};
use mas_jose::jwt::Jwt;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository},
    user::{BrowserSessionRepository, UserEmailRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{
    ErrorContext, FieldError, FormError, TemplateContext, Templates, ToFormState,
    UpstreamExistingLinkContext, UpstreamRegister, UpstreamSuggestLink,
};
use minijinja::Environment;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use ulid::Ulid;

use super::UpstreamSessionsCookie;
use crate::{impl_from_error_for_route, views::shared::OptionalPostAuthAction, PreferredLanguage};

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
    #[error("Template {template:?} could not be rendered from the upstream provider's response for required claim")]
    RequiredAttributeRender {
        template: String,

        #[source]
        source: minijinja::Error,
    },

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
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(mas_jose::jwt::JwtDecodeError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::LinkNotFound => (StatusCode::NOT_FOUND, "Link not found").into_response(),
            Self::Internal(e) => FancyError::from(e).into_response(),
            e => FancyError::from(e).into_response(),
        };

        (SentryEventID::from(event_id), response).into_response()
    }
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
    environment: &Environment,
    template: &str,
    action: &UpstreamOAuthProviderImportAction,
    mut run: impl FnMut(String, bool),
) -> Result<(), RouteError> {
    // If this claim is ignored, we don't need to do anything.
    if action.ignore() {
        return Ok(());
    }

    match environment.render_str(template, ()) {
        Ok(value) if value.is_empty() => { /* Do nothing on empty strings */ }

        Ok(value) => run(value, action.is_forced()),

        Err(source) => {
            if action.is_required() {
                return Err(RouteError::RequiredAttributeRender {
                    template: template.to_owned(),
                    source,
                });
            }

            tracing::warn!(error = &source as &dyn std::error::Error, %template, "Error while rendering template");
        }
    }

    Ok(())
}

#[derive(Deserialize, Serialize)]
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

impl ToFormState for FormData {
    type Field = mas_templates::UpstreamRegisterFormField;
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
    mut policy: Policy,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
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

            post_auth_action.go_next(&url_builder).into_response()
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
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            Html(templates.render_upstream_oauth2_link_mismatch(&ctx)?).into_response()
        }

        (Some(user_session), None) => {
            // Session not linked, but user logged in: suggest linking account
            let ctx = UpstreamSuggestLink::new(&link)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            Html(templates.render_upstream_oauth2_suggest_link(&ctx)?).into_response()
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

            post_auth_action.go_next(&url_builder).into_response()
        }

        (None, None) => {
            // Session not linked and used not logged in: suggest creating an
            // account or logging in an existing user
            let id_token = upstream_session
                .id_token()
                .map(Jwt::<'_, minijinja::Value>::try_from)
                .transpose()?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound)?;

            let payload = id_token
                .map(|id_token| id_token.into_parts().1)
                .unwrap_or_default();

            let mut ctx = UpstreamRegister::default();

            let env = {
                let mut e = Environment::new();
                e.add_global("user", payload);
                e
            };

            import_claim(
                &env,
                provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.name }}"),
                &provider.claims_imports.displayname,
                |value, force| {
                    ctx.set_display_name(value, force);
                },
            )?;

            import_claim(
                &env,
                provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.email }}"),
                &provider.claims_imports.email,
                |value, force| {
                    ctx.set_email(value, force);
                },
            )?;

            let mut forced_localpart = None;
            import_claim(
                &env,
                provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.preferred_username }}"),
                &provider.claims_imports.localpart,
                |value, force| {
                    if force {
                        // We want to run the policy check on the username if it is forced
                        forced_localpart = Some(value.clone());
                    }

                    ctx.set_localpart(value, force);
                },
            )?;

            // Run the policy check and check for existing users
            if let Some(localpart) = forced_localpart {
                let maybe_existing_user = repo.user().find_by_username(&localpart).await?;
                if let Some(existing_user) = maybe_existing_user {
                    // The mapper returned a username which already exists, but isn't linked to
                    // this upstream user.
                    warn!(username = %localpart, user_id = %existing_user.id, "Localpart template returned an existing username");

                    // TODO: translate
                    let ctx = ErrorContext::new()
                        .with_code("User exists")
                        .with_description(format!(
                            r#"Upstream account provider returned {localpart:?} as username,
                            which is not linked to that upstream account"#
                        ))
                        .with_language(&locale);

                    return Ok((
                        cookie_jar,
                        Html(templates.render_error(&ctx)?).into_response(),
                    ));
                }

                let res = policy
                    .evaluate_upstream_oauth_register(&localpart, None)
                    .await?;

                if !res.valid() {
                    // TODO: translate
                    let ctx = ErrorContext::new()
                        .with_code("Policy error")
                        .with_description(format!(
                            r#"Upstream account provider returned {localpart:?} as username,
                            which does not pass the policy check: {res}"#
                        ))
                        .with_language(&locale);

                    return Ok((
                        cookie_jar,
                        Html(templates.render_error(&ctx)?).into_response(),
                    ));
                }
            }

            let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

            Html(templates.render_upstream_oauth2_do_register(&ctx)?).into_response()
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
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    Path(link_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<FormData>>,
) -> Result<Response, RouteError> {
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

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_session(&mut repo).await?;
    let form_state = form.to_form_state();

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
                .map(Jwt::<'_, minijinja::Value>::try_from)
                .transpose()?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::ProviderNotFound)?;

            let payload = id_token
                .map(|id_token| id_token.into_parts().1)
                .unwrap_or_default();

            let provider_email_verified = payload
                .get_item(&minijinja::Value::from("email_verified"))
                .map(|v| v.is_true())
                .unwrap_or(false);

            // Let's try to import the claims from the ID token
            let env = {
                let mut e = Environment::new();
                e.add_global("user", payload);
                e
            };

            // Create a template context in case we need to re-render because of an error
            let mut ctx = UpstreamRegister::default();

            let mut name = None;
            import_claim(
                &env,
                provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.name }}"),
                &provider.claims_imports.displayname,
                |value, force| {
                    // Import the display name if it is either forced or the user has requested it
                    if force || import_display_name {
                        name = Some(value.clone());
                    }

                    ctx.set_display_name(value, force);
                },
            )?;

            let mut email = None;
            import_claim(
                &env,
                provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.email }}"),
                &provider.claims_imports.email,
                |value, force| {
                    // Import the email if it is either forced or the user has requested it
                    if force || import_email {
                        email = Some(value.clone());
                    }

                    ctx.set_email(value, force);
                },
            )?;

            let mut username = username;
            import_claim(
                &env,
                provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or("{{ user.preferred_username }}"),
                &provider.claims_imports.localpart,
                |value, force| {
                    // If the username is forced, override whatever was in the form
                    if force {
                        username = Some(value.clone());
                    }

                    ctx.set_localpart(value, force);
                },
            )?;

            let username = username.filter(|s| !s.is_empty());

            let Some(username) = username else {
                let form_state = form_state.with_error_on_field(
                    mas_templates::UpstreamRegisterFormField::Username,
                    FieldError::Required,
                );

                let ctx = ctx
                    .with_form_state(form_state)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);
                return Ok((
                    cookie_jar,
                    Html(templates.render_upstream_oauth2_do_register(&ctx)?),
                )
                    .into_response());
            };

            // Check if there is an existing user
            let existing_user = repo.user().find_by_username(&username).await?;
            if let Some(_existing_user) = existing_user {
                // If there is an existing user, we can't create a new one
                // with the same username

                let form_state = form_state.with_error_on_field(
                    mas_templates::UpstreamRegisterFormField::Username,
                    FieldError::Exists,
                );

                let ctx = ctx
                    .with_form_state(form_state)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);
                return Ok((
                    cookie_jar,
                    Html(templates.render_upstream_oauth2_do_register(&ctx)?),
                )
                    .into_response());
            }

            // Policy check
            let res = policy
                .evaluate_upstream_oauth_register(&username, email.as_deref())
                .await?;
            if !res.valid() {
                let form_state =
                    res.violations
                        .into_iter()
                        .fold(form_state, |form_state, violation| {
                            match violation.field.as_deref() {
                                Some("username") => form_state.with_error_on_field(
                                    mas_templates::UpstreamRegisterFormField::Username,
                                    FieldError::Policy {
                                        message: violation.msg,
                                    },
                                ),
                                _ => form_state.with_error_on_form(FormError::Policy {
                                    message: violation.msg,
                                }),
                            }
                        });

                let ctx = ctx
                    .with_form_state(form_state)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);
                return Ok((
                    cookie_jar,
                    Html(templates.render_upstream_oauth2_do_register(&ctx)?),
                )
                    .into_response());
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
                // Mark the email as verified according to the policy and whether the provider
                // claims it is, and make it the primary email.
                if provider
                    .claims_imports
                    .verify_email
                    .should_mark_as_verified(provider_email_verified)
                {
                    let user_email = repo
                        .user_email()
                        .mark_as_verified(&clock, user_email)
                        .await?;

                    repo.user_email().set_as_primary(&user_email).await?;
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

    Ok((cookie_jar, post_auth_action.go_next(&url_builder)).into_response())
}
