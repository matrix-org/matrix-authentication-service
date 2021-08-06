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

use sqlx::PgPool;
use warp::{Filter, Rejection, Reply};

use crate::{config::RootConfig, templates::Templates};

mod health;
mod oauth2;
mod views;

use self::{health::filter as health, oauth2::filter as oauth2, views::filter as views};

pub fn root(
    pool: &PgPool,
    templates: &Templates,
    config: &RootConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    health(pool)
        .or(oauth2(pool, templates, &config.oauth2, &config.cookies))
        .or(views(pool, templates, &config.csrf, &config.cookies))
        //.or(warp::get().map(|| StatusCode::NOT_FOUND)) <- This messes up the error reporting
        .with(warp::log(module_path!()))
}
