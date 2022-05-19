// Copyright 2022 The Matrix.org Foundation C.I.C.
//
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

use std::collections::HashMap;

use axum::{
    extract::Path,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{FancyError, SessionInfoExt};
use mas_config::Encrypter;
use mas_data_model::Device;
use mas_router::Route;
use mas_storage::compat::{fullfill_compat_sso_login, get_compat_sso_login_by_id};
use rand::thread_rng;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Serialize)]
struct AllParams<'s> {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    existing_params: Option<HashMap<&'s str, &'s str>>,

    #[serde(rename = "loginToken")]
    login_token: &'s str,
}

pub async fn get(
    Extension(pool): Extension<PgPool>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(id): Path<i64>,
) -> Result<Response, FancyError> {
    let mut txn = pool.begin().await?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut txn).await?;

    let session = if let Some(session) = maybe_session {
        session
    } else {
        // If there is no session, redirect to the login screen
        let login = mas_router::Login::and_continue_compat_sso_login(id);
        return Ok((cookie_jar, login.go()).into_response());
    };

    let login = get_compat_sso_login_by_id(&mut txn, id).await?;

    let redirect_uri = {
        let mut redirect_uri = login.redirect_uri.clone();
        let existing_params = redirect_uri
            .query()
            .map(serde_urlencoded::from_str)
            .transpose()?
            .unwrap_or_default();

        let params = AllParams {
            existing_params,
            login_token: &login.token,
        };
        let query = serde_urlencoded::to_string(&params)?;
        redirect_uri.set_query(Some(&query));
        redirect_uri
    };

    let device = Device::generate(&mut thread_rng());
    let _login = fullfill_compat_sso_login(&mut txn, session.user, login, device).await?;

    txn.commit().await?;

    Ok((cookie_jar, Redirect::to(redirect_uri.as_str())).into_response())
}
