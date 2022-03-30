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
    extract::Extension,
    response::{IntoResponse, Response},
    Json,
};
use mas_axum_utils::{internal_error, user_authorization::UserAuthorization};
use oauth2_types::scope;
use serde::Serialize;
use serde_with::skip_serializing_none;
use sqlx::PgPool;

#[skip_serializing_none]
#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

pub async fn get(
    Extension(pool): Extension<PgPool>,
    user_authorization: UserAuthorization,
) -> Result<impl IntoResponse, Response> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(internal_error)
        .map_err(IntoResponse::into_response)?;

    let session = user_authorization
        .protected(&mut conn)
        .await
        .map_err(IntoResponse::into_response)?;

    let user = session.browser_session.user;
    let mut res = UserInfo {
        sub: user.sub,
        username: user.username,
        email: None,
        email_verified: None,
    };

    if session.scope.contains(&scope::EMAIL) {
        if let Some(email) = user.primary_email {
            res.email_verified = Some(email.confirmed_at.is_some());
            res.email = Some(email.email);
        }
    }

    Ok(Json(res))
}
