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
    extract::{Extension, Path},
    response::{Html, IntoResponse},
};
use axum_extra::extract::PrivateCookieJar;
use chrono::Duration;
use mas_axum_utils::{csrf::CsrfExt, FancyError, SessionInfoExt};
use mas_config::Encrypter;
use mas_storage::user::{
    consume_email_verification, lookup_user_email_verification_code, mark_user_email_as_verified,
};
use mas_templates::{EmptyContext, TemplateContext, Templates};
use sqlx::PgPool;

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Path(code): Path<String>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<impl IntoResponse, FancyError> {
    let mut txn = pool.begin().await?;

    // TODO: make those 8 hours configurable
    let verification =
        lookup_user_email_verification_code(&mut txn, &code, Duration::hours(8)).await?;

    // TODO: display nice errors if the code was already consumed or expired
    let verification = consume_email_verification(&mut txn, verification).await?;

    let _email = mark_user_email_as_verified(&mut txn, verification.email).await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let ctx = EmptyContext
        .maybe_with_session(maybe_session)
        .with_csrf(csrf_token.form_value());

    let content = templates.render_email_verification_done(&ctx).await?;

    txn.commit().await?;

    Ok((cookie_jar, Html(content)))
}
