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
    extract::{Extension, Form},
    response::{IntoResponse, Redirect},
};
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    fancy_error, FancyError, PrivateCookieJar, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_storage::user::end_session;
use mas_templates::Templates;
use sqlx::PgPool;

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<impl IntoResponse, FancyError> {
    let mut txn = pool.begin().await.map_err(fancy_error(templates.clone()))?;

    cookie_jar
        .verify_form(form)
        .map_err(fancy_error(templates.clone()))?;

    let (session_info, mut cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut txn)
        .await
        .map_err(fancy_error(templates.clone()))?;

    if let Some(session) = maybe_session {
        end_session(&mut txn, &session)
            .await
            .map_err(fancy_error(templates.clone()))?;
        cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());
    }

    txn.commit().await.map_err(fancy_error(templates))?;

    Ok((cookie_jar, Redirect::to("/login")))
}
