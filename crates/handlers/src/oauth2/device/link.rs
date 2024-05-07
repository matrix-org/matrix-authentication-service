// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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
    response::IntoResponse,
};
use axum_extra::response::Html;
use mas_axum_utils::{cookies::CookieJar, FancyError};
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository};
use mas_templates::{
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormState, TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::PreferredLanguage;

#[derive(Serialize, Deserialize)]
pub struct Params {
    code: String,
}

#[tracing::instrument(name = "handlers.oauth2.device.link.get", skip_all, err)]
pub(crate) async fn get(
    clock: BoxClock,
    mut repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    query: Option<Query<Params>>,
) -> Result<impl IntoResponse, FancyError> {
    let mut form_state = FormState::default();

    // If we have a code in query, find it in the database
    if let Some(Query(params)) = query {
        // Save the form state so that we echo back the code
        form_state = FormState::from_form(&params);

        // Find the code in the database
        let code = params.code.to_uppercase();
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&code)
            .await?
            // XXX: We should have different error messages for already exchanged and expired
            .filter(|grant| grant.is_pending())
            .filter(|grant| grant.expires_at > clock.now());

        if let Some(grant) = grant {
            // This is a valid code, redirect to the consent page
            // This will in turn redirect to the login page if the user is not logged in
            let destination = url_builder.redirect(&mas_router::DeviceCodeConsent::new(grant.id));

            return Ok((cookie_jar, destination).into_response());
        }

        // The code isn't valid, set an error on the form
        form_state = form_state.with_error_on_field(DeviceLinkFormField::Code, FieldError::Invalid);
    };

    // Rendre the form
    let ctx = DeviceLinkContext::new()
        .with_form_state(form_state)
        .with_language(locale);

    let content = templates.render_device_link(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}
