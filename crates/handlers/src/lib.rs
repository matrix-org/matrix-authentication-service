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
#![deny(clippy::all, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::unused_async // Some warp filters need that
)]

use std::sync::Arc;

use axum::{extract::Extension, routing::get, Router};
use mas_axum_utils::UrlBuilder;
use mas_config::{Encrypter, RootConfig};
use mas_email::Mailer;
use mas_jose::StaticKeystore;
use mas_templates::Templates;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter, Reply};

mod health;
mod oauth2;
mod views;

use self::{oauth2::filter as oauth2, views::filter as views};

#[must_use]
pub fn root(
    pool: &PgPool,
    templates: &Templates,
    key_store: &Arc<StaticKeystore>,
    encrypter: &Encrypter,
    mailer: &Mailer,
    config: &RootConfig,
) -> BoxedFilter<(impl Reply,)> {
    let oauth2 = oauth2(pool, templates, key_store, encrypter, &config.http);
    let views = views(
        pool,
        templates,
        mailer,
        encrypter,
        &config.http,
        &config.csrf,
    );

    let filter = views.or(oauth2);

    filter.with(warp::log(module_path!())).boxed()
}

#[must_use]
pub fn router<B: Send + 'static>(
    pool: &PgPool,
    templates: &Templates,
    key_store: &Arc<StaticKeystore>,
    encrypter: &Encrypter,
    mailer: &Mailer,
    url_builder: &UrlBuilder,
) -> Router<B> {
    Router::new()
        .route("/", get(self::views::index::get))
        .route("/health", get(self::health::get))
        .fallback(mas_static_files::Assets)
        .layer(Extension(pool.clone()))
        .layer(Extension(templates.clone()))
        .layer(Extension(key_store.clone()))
        .layer(Extension(encrypter.clone()))
        .layer(Extension(url_builder.clone()))
        .layer(Extension(mailer.clone()))
}
