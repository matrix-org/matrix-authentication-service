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

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use mas_axum_utils::{cookies::CookieJar, csrf::CsrfExt, FancyError, SessionInfoExt};
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng};
use mas_templates::{IndexContext, TemplateContext, Templates};

use crate::{preferred_language::PreferredLanguage, BoundActivityTracker};

#[tracing::instrument(name = "handlers.views.index.get", skip_all, err)]
pub async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    activity_tracker: BoundActivityTracker,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    PreferredLanguage(locale): PreferredLanguage,
) -> Result<impl IntoResponse, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let session = session_info.load_session(&mut repo).await?;

    if let Some(session) = session.as_ref() {
        activity_tracker
            .record_browser_session(&clock, session)
            .await;
    }

    let ctx = IndexContext::new(url_builder.oidc_discovery())
        .maybe_with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_index(&ctx)?;

    Ok((cookie_jar, Html(content)))
}
