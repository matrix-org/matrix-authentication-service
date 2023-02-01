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

pub mod emails;
pub mod password;

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{csrf::CsrfExt, FancyError, SessionInfoExt};
use mas_keystore::Encrypter;
use mas_router::Route;
use mas_storage::{
    user::{BrowserSessionRepository, UserEmailRepository},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{AccountContext, TemplateContext, Templates};

#[tracing::instrument(name = "handlers.views.account.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, login.go()).into_response());
    };

    let active_sessions = repo.browser_session().count_active(&session.user).await?;

    let emails = repo.user_email().all(&session.user).await?;

    let ctx = AccountContext::new(active_sessions, emails)
        .with_session(session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_account_index(&ctx).await?;

    Ok((cookie_jar, Html(content)).into_response())
}
