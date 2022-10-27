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

use anyhow::Context;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use mas_axum_utils::{jwt::JwtResponse, user_authorization::UserAuthorization, FancyError};
use mas_jose::{
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
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
    State(url_builder): State<UrlBuilder>,
    State(pool): State<PgPool>,
    State(key_store): State<Keystore>,
    user_authorization: UserAuthorization,
) -> Result<Response, FancyError> {
    // TODO: error handling
    let (_clock, mut rng) = crate::rng_and_clock()?;
    let mut conn = pool.acquire().await?;

    let session = user_authorization.protected(&mut *conn).await?;

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
        let key = key_store
            .signing_key_for_algorithm(&alg)
            .context("no suitable key found")?;

        let signer = key.params().signing_key_for_alg(&alg)?;
        let header = JsonWebSignatureHeader::new(alg)
            .with_kid(key.kid().context("key has no `kid` for some reason")?);

        let user_info = SignedUserInfo {
            iss: url_builder.oidc_issuer().to_string(),
            aud: session.client.client_id,
            user_info,
        };

        let token = Jwt::sign_with_rng(&mut rng, header, user_info, &signer)?;
        Ok(JwtResponse(token).into_response())
    } else {
        Ok(Json(user_info).into_response())
    }
}
