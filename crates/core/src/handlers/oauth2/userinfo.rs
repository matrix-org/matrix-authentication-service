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

use serde::Serialize;
use sqlx::PgPool;
use warp::{Filter, Rejection, Reply};

use crate::{
    config::OAuth2Config,
    filters::authenticate::{authentication, recover_unauthorized},
    storage::oauth2::access_token::OAuth2AccessTokenLookup,
};

#[derive(Serialize)]
struct UserInfo {
    sub: String,
}

pub(super) fn filter(
    pool: &PgPool,
    _config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("oauth2" / "userinfo")
        .and(warp::get().or(warp::post()).unify())
        .and(authentication(pool))
        .and_then(userinfo)
        .recover(recover_unauthorized)
}

async fn userinfo(token: OAuth2AccessTokenLookup) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&UserInfo {
        sub: token.username,
    }))
}
