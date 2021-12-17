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

use hyper::Method;
use mas_config::OAuth2Config;
use mas_data_model::{AccessToken, Session};
use mas_storage::PostgresqlBackend;
use mas_warp_utils::filters::{
    authenticate::{authentication, recover_unauthorized},
    cors::cors,
};
use serde::Serialize;
use sqlx::PgPool;
use warp::{Filter, Rejection, Reply};

#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
}

pub(super) fn filter(
    pool: &PgPool,
    _config: &OAuth2Config,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::path!("oauth2" / "userinfo").and(
        warp::get()
            .or(warp::post())
            .unify()
            .and(authentication(pool))
            .and_then(userinfo)
            .recover(recover_unauthorized)
            .with(cors().allow_methods([Method::GET, Method::POST])),
    )
}

async fn userinfo(
    _token: AccessToken<PostgresqlBackend>,
    session: Session<PostgresqlBackend>,
) -> Result<impl Reply, Rejection> {
    let user = session.browser_session.user;
    Ok(warp::reply::json(&UserInfo {
        sub: user.sub,
        username: user.username,
    }))
}
