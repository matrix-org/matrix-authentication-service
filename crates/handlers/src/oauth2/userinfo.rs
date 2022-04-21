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

use std::sync::Arc;

use axum::{
    extract::Extension,
    response::{IntoResponse, Response},
    Json, TypedHeader,
};
use headers::ContentType;
use hyper::StatusCode;
use mas_axum_utils::{internal_error, user_authorization::UserAuthorization, UrlBuilder};
use mas_jose::{DecodedJsonWebToken, SigningKeystore, StaticKeystore};
use mime::Mime;
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

#[derive(Serialize)]
struct SignedUserInfo {
    iss: String,
    aud: String,
    #[serde(flatten)]
    user_info: UserInfo,
}

pub async fn get(
    Extension(url_builder): Extension<UrlBuilder>,
    Extension(pool): Extension<PgPool>,
    Extension(key_store): Extension<Arc<StaticKeystore>>,
    user_authorization: UserAuthorization,
) -> Result<Response, Response> {
    // TODO: error handling
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
    let mut user_info = UserInfo {
        sub: user.sub,
        username: user.username,
        email: None,
        email_verified: None,
    };

    if session.scope.contains(&scope::EMAIL) {
        if let Some(email) = user.primary_email {
            user_info.email_verified = Some(email.confirmed_at.is_some());
            user_info.email = Some(email.email);
        }
    }

    if let Some(alg) = session.client.userinfo_signed_response_alg {
        let header = key_store
            .prepare_header(alg)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            .map_err(IntoResponse::into_response)?;

        let user_info = SignedUserInfo {
            iss: url_builder.oidc_issuer().to_string(),
            aud: session.client.client_id,
            user_info,
        };

        let user_info = DecodedJsonWebToken::new(header, user_info);
        let user_info = user_info
            .sign(key_store.as_ref())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            .map_err(IntoResponse::into_response)?;

        let token = user_info.serialize();
        let application_jwt: Mime = "application/jwt".parse().unwrap();
        let content_type = ContentType::from(application_jwt);
        Ok((TypedHeader(content_type), token).into_response())
    } else {
        Ok(Json(user_info).into_response())
    }
}
