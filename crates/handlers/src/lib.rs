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

#![forbid(unsafe_code)]
#![deny(clippy::all, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::unused_async // Some axum handlers need that
)]

use std::{sync::Arc, time::Duration};

use axum::{
    body::HttpBody,
    extract::Extension,
    routing::{get, on, post, MethodFilter},
    Router,
};
use hyper::header::AUTHORIZATION;
use mas_axum_utils::UrlBuilder;
use mas_config::Encrypter;
use mas_email::Mailer;
use mas_http::CorsLayerExt;
use mas_jose::StaticKeystore;
use mas_templates::Templates;
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};

mod health;
mod oauth2;
mod views;

#[must_use]
pub fn router<B>(
    pool: &PgPool,
    templates: &Templates,
    key_store: &Arc<StaticKeystore>,
    encrypter: &Encrypter,
    mailer: &Mailer,
    url_builder: &UrlBuilder,
) -> Router<B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
{
    // All those routes are API-like, with a common CORS layer
    let api_router = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(self::oauth2::discovery::get),
        )
        .route("/oauth2/keys.json", get(self::oauth2::keys::get))
        .route(
            "/oauth2/userinfo",
            on(
                MethodFilter::POST | MethodFilter::GET,
                self::oauth2::userinfo::get,
            ),
        )
        .route(
            "/oauth2/introspect",
            post(self::oauth2::introspection::post),
        )
        .route("/oauth2/token", post(self::oauth2::token::post))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_otel_headers([AUTHORIZATION])
                .max_age(Duration::from_secs(60 * 60)),
        );

    Router::new()
        .route("/", get(self::views::index::get))
        .route("/health", get(self::health::get))
        .route(
            "/login",
            get(self::views::login::get).post(self::views::login::post),
        )
        .route("/logout", post(self::views::logout::post))
        .route(
            "/reauth",
            get(self::views::reauth::get).post(self::views::reauth::post),
        )
        .route(
            "/register",
            get(self::views::register::get).post(self::views::register::post),
        )
        .route("/verify/:code", get(self::views::verify::get))
        .route("/account", get(self::views::account::get))
        .route(
            "/account/password",
            get(self::views::account::password::get).post(self::views::account::password::post),
        )
        .route(
            "/account/emails",
            get(self::views::account::emails::get).post(self::views::account::emails::post),
        )
        .route("/oauth2/authorize", get(self::oauth2::authorization::get))
        .route(
            "/oauth2/authorize/step",
            get(self::oauth2::authorization::step_get),
        )
        .merge(api_router)
        .fallback(mas_static_files::Assets)
        .layer(Extension(pool.clone()))
        .layer(Extension(templates.clone()))
        .layer(Extension(key_store.clone()))
        .layer(Extension(encrypter.clone()))
        .layer(Extension(url_builder.clone()))
        .layer(Extension(mailer.clone()))
}
