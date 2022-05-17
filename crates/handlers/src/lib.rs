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

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::HttpBody,
    extract::Extension,
    response::{Html, IntoResponse},
    routing::{get, on, post, MethodFilter},
    Router,
};
use headers::HeaderName;
use hyper::header::{ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_LANGUAGE, CONTENT_TYPE};
use mas_config::{Encrypter, MatrixConfig};
use mas_email::Mailer;
use mas_http::CorsLayerExt;
use mas_jose::StaticKeystore;
use mas_router::{Route, UrlBuilder};
use mas_templates::{ErrorContext, Templates};
use sqlx::PgPool;
use tower::util::ThenLayer;
use tower_http::cors::{Any, CorsLayer};

mod compat;
mod health;
mod oauth2;
mod views;

#[must_use]
#[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
pub fn router<B>(
    pool: &PgPool,
    templates: &Templates,
    key_store: &Arc<StaticKeystore>,
    encrypter: &Encrypter,
    mailer: &Mailer,
    url_builder: &UrlBuilder,
    matrix_config: &MatrixConfig,
) -> Router<B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
{
    // All those routes are API-like, with a common CORS layer
    let api_router = Router::new()
        .route(
            mas_router::ChangePasswordDiscovery::route(),
            get(|| async { mas_router::AccountPassword.go() }),
        )
        .route(
            mas_router::OidcConfiguration::route(),
            get(self::oauth2::discovery::get),
        )
        .route(
            mas_router::Webfinger::route(),
            get(self::oauth2::webfinger::get),
        )
        .route(
            mas_router::OAuth2Keys::route(),
            get(self::oauth2::keys::get),
        )
        .route(
            mas_router::OidcUserinfo::route(),
            on(
                MethodFilter::POST | MethodFilter::GET,
                self::oauth2::userinfo::get,
            ),
        )
        .route(
            mas_router::OAuth2Introspection::route(),
            post(self::oauth2::introspection::post),
        )
        .route(
            mas_router::OAuth2TokenEndpoint::route(),
            post(self::oauth2::token::post),
        )
        .route(
            mas_router::OAuth2RegistrationEndpoint::route(),
            post(self::oauth2::registration::post),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_otel_headers([
                    AUTHORIZATION,
                    ACCEPT,
                    ACCEPT_LANGUAGE,
                    CONTENT_LANGUAGE,
                    CONTENT_TYPE,
                ])
                .max_age(Duration::from_secs(60 * 60)),
        );

    let compat_router = Router::new()
        .route(
            mas_router::CompatLogin::route(),
            get(self::compat::login::get).post(self::compat::login::post),
        )
        .route(
            mas_router::CompatLogout::route(),
            post(self::compat::logout::post),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_otel_headers([
                    AUTHORIZATION,
                    ACCEPT,
                    ACCEPT_LANGUAGE,
                    CONTENT_LANGUAGE,
                    CONTENT_TYPE,
                    HeaderName::from_static("x-requested-with"),
                ])
                .max_age(Duration::from_secs(60 * 60)),
        );

    let human_router = {
        let templates = templates.clone();
        Router::new()
            .route(mas_router::Index::route(), get(self::views::index::get))
            .route(mas_router::Healthcheck::route(), get(self::health::get))
            .route(
                mas_router::Login::route(),
                get(self::views::login::get).post(self::views::login::post),
            )
            .route(mas_router::Logout::route(), post(self::views::logout::post))
            .route(
                mas_router::Reauth::route(),
                get(self::views::reauth::get).post(self::views::reauth::post),
            )
            .route(
                mas_router::Register::route(),
                get(self::views::register::get).post(self::views::register::post),
            )
            .route(
                mas_router::VerifyEmail::route(),
                get(self::views::verify::get),
            )
            .route(mas_router::Account::route(), get(self::views::account::get))
            .route(
                mas_router::AccountPassword::route(),
                get(self::views::account::password::get).post(self::views::account::password::post),
            )
            .route(
                mas_router::AccountEmails::route(),
                get(self::views::account::emails::get).post(self::views::account::emails::post),
            )
            .route(
                mas_router::OAuth2AuthorizationEndpoint::route(),
                get(self::oauth2::authorization::get),
            )
            .route(
                mas_router::ContinueAuthorizationGrant::route(),
                get(self::oauth2::authorization::complete::get),
            )
            .route(
                mas_router::Consent::route(),
                get(self::oauth2::consent::get).post(self::oauth2::consent::post),
            )
            .layer(ThenLayer::new(
                move |result: Result<axum::response::Response, Infallible>| async move {
                    let response = result.unwrap();

                    if response.status().is_server_error() {
                        // Error responses should have an ErrorContext attached to them
                        let ext = response.extensions().get::<ErrorContext>();
                        if let Some(ctx) = ext {
                            if let Ok(res) = templates.render_error(ctx).await {
                                let (mut parts, _original_body) = response.into_parts();
                                parts.headers.remove(CONTENT_TYPE);
                                return Ok((parts, Html(res)).into_response());
                            }
                        }
                    }

                    Ok(response)
                },
            ))
    };

    human_router
        .merge(api_router)
        .merge(compat_router)
        .layer(Extension(pool.clone()))
        .layer(Extension(templates.clone()))
        .layer(Extension(key_store.clone()))
        .layer(Extension(encrypter.clone()))
        .layer(Extension(url_builder.clone()))
        .layer(Extension(mailer.clone()))
        .layer(Extension(matrix_config.clone()))
}
