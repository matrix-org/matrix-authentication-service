// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use chrono::Utc;
use headers::{authorization::Bearer, Authorization};
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use warp::{Filter, Rejection};

use super::{database::with_connection, headers::with_typed_header};
use crate::{
    errors::WrapError,
    storage::oauth2::access_token::{lookup_access_token, OAuth2AccessTokenLookup},
    tokens,
};

pub fn with_authentication(
    pool: &PgPool,
) -> impl Filter<Extract = (OAuth2AccessTokenLookup,), Error = Rejection> + Clone + Send + Sync + 'static
{
    with_connection(pool)
        .and(with_typed_header())
        .and_then(authenticate)
}

async fn authenticate(
    mut conn: PoolConnection<Postgres>,
    auth: Authorization<Bearer>,
) -> Result<OAuth2AccessTokenLookup, Rejection> {
    let token = auth.0.token();
    let token_type = tokens::check(token).wrap_error()?;
    if token_type != tokens::TokenType::AccessToken {
        return Err(anyhow::anyhow!("wrong token type")).wrap_error();
    }

    let token = lookup_access_token(&mut conn, token).await.wrap_error()?;
    let exp = token.exp();

    // Check it is active and did not expire
    if !token.active || exp < Utc::now() {
        return Err(anyhow::anyhow!("token expired")).wrap_error();
    }

    Ok(token)
}
