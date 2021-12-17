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

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::implicit_hasher)]
#![allow(clippy::unused_async)] // Some warp filters need that

use mas_config::RootConfig;
use mas_static_files::filter as static_files;
use mas_templates::Templates;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter, Reply};

mod health;
mod oauth2;
mod views;

use self::{health::filter as health, oauth2::filter as oauth2, views::filter as views};

#[must_use]
pub fn root(
    pool: &PgPool,
    templates: &Templates,
    config: &RootConfig,
) -> BoxedFilter<(impl Reply,)> {
    health(pool)
        .or(oauth2(pool, templates, &config.oauth2, &config.cookies))
        .or(views(
            pool,
            templates,
            &config.oauth2,
            &config.csrf,
            &config.cookies,
        ))
        .or(static_files(config.http.web_root.clone()))
        .with(warp::log(module_path!()))
        .boxed()
}
