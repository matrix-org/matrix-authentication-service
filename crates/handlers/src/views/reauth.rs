// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::{
    user::{BrowserSessionRepository, UserPasswordRepository},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{ReauthContext, TemplateContext, Templates};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::passwords::PasswordManager;

#[derive(Deserialize, Debug)]
pub(crate) struct ReauthForm {
    password: String,
}

#[tracing::instrument(name = "handlers.views.reauth.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, login.go()).into_response());
    };

    let ctx = ReauthContext::default();
    let next = query.load_context(&mut repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_session(session).with_csrf(csrf_token.form_value());

    let content = templates.render_reauth(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.reauth.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(password_manager): State<PasswordManager>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<ReauthForm>>,
) -> Result<Response, FancyError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, login.go()).into_response());
    };

    // Load the user password
    let user_password = repo
        .user_password()
        .active(&session.user)
        .await?
        .context("User has no password")?;

    let password = Zeroizing::new(form.password.as_bytes().to_vec());

    // TODO: recover from errors
    // Verify the password, and upgrade it on-the-fly if needed
    let new_password_hash = password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await?;

    let user_password = if let Some((version, new_password_hash)) = new_password_hash {
        // Save the upgraded password
        repo.user_password()
            .add(
                &mut rng,
                &clock,
                &session.user,
                version,
                new_password_hash,
                Some(&user_password),
            )
            .await?
    } else {
        user_password
    };

    // Mark the session as authenticated by the password
    let session = repo
        .browser_session()
        .authenticate_with_password(&mut rng, &clock, session, &user_password)
        .await?;

    let cookie_jar = cookie_jar.set_session(&session);
    repo.save().await?;

    let reply = query.go_next();
    Ok((cookie_jar, reply).into_response())
}
