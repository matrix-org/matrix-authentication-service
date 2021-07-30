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

use hyper::StatusCode;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter};

use crate::{config::RootConfig, templates::Templates};

mod health;
mod oauth2;
mod views;

use self::{health::filter as health, oauth2::filter as oauth2, views::filter as views};

pub fn root(
    pool: &PgPool,
    templates: &Templates,
    config: &RootConfig,
) -> BoxedFilter<(impl warp::Reply,)> {
    health(pool)
        .or(oauth2(&config.oauth2))
        .or(views(pool, templates, &config.csrf, &config.cookies))
        .or(warp::get().map(|| StatusCode::NOT_FOUND))
        .with(warp::log(module_path!()))
        .boxed()
}
