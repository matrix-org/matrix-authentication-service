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

use mas_data_model::{AccessToken, Session};
use mas_storage::PostgresqlBackend;
use mas_warp_utils::filters::{
    self,
    authenticate::{authentication, recover_unauthorized},
};
use serde::Serialize;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
}

pub(super) fn filter(pool: &PgPool) -> BoxedFilter<(Box<dyn Reply>,)> {
    warp::path!("oauth2" / "userinfo")
        .and(filters::trace::name("GET /oauth2/userinfo"))
        .and(
            warp::get()
                .or(warp::post())
                .unify()
                .and(authentication(pool))
                .and_then(userinfo)
                .recover(recover_unauthorized)
                .unify(),
        )
        .boxed()
}

async fn userinfo(
    _token: AccessToken<PostgresqlBackend>,
    session: Session<PostgresqlBackend>,
) -> Result<Box<dyn Reply>, Rejection> {
    let user = session.browser_session.user;
    Ok(Box::new(warp::reply::json(&UserInfo {
        sub: user.sub,
        username: user.username,
    })))
}
