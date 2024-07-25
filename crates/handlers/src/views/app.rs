// Copyright 2023 The Matrix.org Foundation C.I.C.
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
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use mas_axum_utils::{cookies::CookieJar, FancyError, SessionInfoExt};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxClock, BoxRepository};
use mas_templates::{AppContext, TemplateContext, Templates};

use crate::{BoundActivityTracker, PreferredLanguage};

#[tracing::instrument(name = "handlers.views.app.get", skip_all, err)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    action: Option<Query<mas_router::AccountAction>>,
    mut repo: BoxRepository,
    clock: BoxClock,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, FancyError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let session = session_info.load_session(&mut repo).await?;
    let action = action.map(|Query(a)| a);

    // TODO: keep the full path, not just the action
    let Some(session) = session else {
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::Login::and_then(
                PostAuthAction::manage_account(action),
            )),
        )
            .into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all, err)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
) -> Result<impl IntoResponse, FancyError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok(Html(content).into_response())
}
