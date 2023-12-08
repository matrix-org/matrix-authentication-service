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
    response::{IntoResponse, Response},
    Form,
};
use axum_extra::response::Html;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError,
};
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng};
use mas_templates::{
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormState, TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::PreferredLanguage;

// We use this struct for both the form and the query parameters. This is useful
// to build a form state from the query parameters. The query parameter is only
// really used when the `verification_uri_complete` feature of the device code
// grant is used.
#[derive(Serialize, Deserialize)]
pub struct Params {
    code: String,
}

#[tracing::instrument(name = "handlers.oauth2.device.link.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    cookie_jar: CookieJar,
    query: Option<Query<Params>>,
) -> Result<impl IntoResponse, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let mut form_state = FormState::default();

    // XXX: right now we just get the code from the query to pre-fill the form. We
    // may want to make the form readonly instead at some point? tbd
    if let Some(Query(params)) = query {
        // Validate that it's a full code
        if params.code.len() == 6 && params.code.chars().all(|c| c.is_ascii_alphanumeric()) {
            form_state = FormState::from_form(&params);
        }
    };

    let ctx = DeviceLinkContext::new()
        .with_form_state(form_state)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_device_link(&ctx)?;

    Ok((cookie_jar, Html(content)))
}

#[tracing::instrument(name = "handlers.oauth2.device.link.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<Params>>,
) -> Result<Response, FancyError> {
    let form = cookie_jar.verify_form(&clock, form)?;
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let code = form.code.to_uppercase();
    let grant = repo
        .oauth2_device_code_grant()
        .find_by_user_code(&code)
        .await?
        // XXX: We should have different error messages for already exchanged and expired
        .filter(|grant| grant.is_pending())
        .filter(|grant| grant.expires_at > clock.now());

    let Some(grant) = grant else {
        let form_state = FormState::from_form(&form)
            .with_error_on_field(DeviceLinkFormField::Code, FieldError::Invalid);

        let ctx = DeviceLinkContext::new()
            .with_form_state(form_state)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_device_link(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    };

    // Redirect to the consent page
    // This will in turn redirect to the login page if the user is not logged in
    let destination = url_builder.redirect(&mas_router::DeviceCodeConsent::new(grant.id));

    Ok((cookie_jar, destination).into_response())
}
