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
#![deny(clippy::all, clippy::str_to_string, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::unused_async // Some axum handlers need that
)]

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::HttpBody,
    extract::FromRef,
    response::{Html, IntoResponse},
    routing::{get, on, post, MethodFilter},
    Router,
};
use headers::HeaderName;
use hyper::header::{ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_LANGUAGE, CONTENT_TYPE};
use mas_email::Mailer;
use mas_http::CorsLayerExt;
use mas_keystore::{Encrypter, Keystore};
use mas_policy::PolicyFactory;
use mas_router::{Route, UrlBuilder};
use mas_templates::{ErrorContext, Templates};
use sqlx::PgPool;
use tower::util::AndThenLayer;
use tower_http::cors::{Any, CorsLayer};

mod app_state;
mod compat;
mod health;
mod oauth2;
mod views;

pub use compat::MatrixHomeserver;

pub use self::app_state::AppState;

#[must_use]
pub fn empty_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    S: Send + Sync + 'static,
{
    Router::with_state_arc(state)
}

#[must_use]
pub fn healthcheck_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    S: Send + Sync + 'static,
    PgPool: FromRef<S>,
{
    Router::with_state_arc(state).route(mas_router::Healthcheck::route(), get(self::health::get))
}

#[must_use]
pub fn discovery_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    S: Send + Sync + 'static,
    Keystore: FromRef<S>,
    UrlBuilder: FromRef<S>,
{
    Router::with_state_arc(state)
        .route(
            mas_router::OidcConfiguration::route(),
            get(self::oauth2::discovery::get),
        )
        .route(
            mas_router::Webfinger::route(),
            get(self::oauth2::webfinger::get),
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
        )
}

#[must_use]
#[allow(clippy::trait_duplication_in_bounds)]
pub fn api_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
    S: Send + Sync + 'static,
    Keystore: FromRef<S>,
    UrlBuilder: FromRef<S>,
    Arc<PolicyFactory>: FromRef<S>,
    PgPool: FromRef<S>,
    Encrypter: FromRef<S>,
{
    // All those routes are API-like, with a common CORS layer
    Router::with_state_arc(state)
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
        )
}

#[must_use]
#[allow(clippy::trait_duplication_in_bounds)]
pub fn compat_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
    S: Send + Sync + 'static,
    UrlBuilder: FromRef<S>,
    PgPool: FromRef<S>,
    MatrixHomeserver: FromRef<S>,
{
    Router::with_state_arc(state)
        .route(
            mas_router::CompatLogin::route(),
            get(self::compat::login::get).post(self::compat::login::post),
        )
        .route(
            mas_router::CompatLogout::route(),
            post(self::compat::logout::post),
        )
        .route(
            mas_router::CompatRefresh::route(),
            post(self::compat::refresh::post),
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
        )
}

#[must_use]
#[allow(clippy::trait_duplication_in_bounds)]
pub fn human_router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
    S: Send + Sync + 'static,
    UrlBuilder: FromRef<S>,
    Arc<PolicyFactory>: FromRef<S>,
    PgPool: FromRef<S>,
    Encrypter: FromRef<S>,
    Templates: FromRef<S>,
    Mailer: FromRef<S>,
{
    let templates = Templates::from_ref(&state);
    Router::with_state_arc(state)
        .route(
            mas_router::ChangePasswordDiscovery::route(),
            get(|| async { mas_router::AccountPassword.go() }),
        )
        .route(mas_router::Index::route(), get(self::views::index::get))
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
            mas_router::AccountVerifyEmail::route(),
            get(self::views::account::emails::verify::get)
                .post(self::views::account::emails::verify::post),
        )
        .route(
            mas_router::AccountAddEmail::route(),
            get(self::views::account::emails::add::get)
                .post(self::views::account::emails::add::post),
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
        .route(
            mas_router::CompatLoginSsoRedirect::route(),
            get(self::compat::login_sso_redirect::get),
        )
        .route(
            mas_router::CompatLoginSsoRedirectIdp::route(),
            get(self::compat::login_sso_redirect::get),
        )
        .route(
            mas_router::CompatLoginSsoComplete::route(),
            get(self::compat::login_sso_complete::get).post(self::compat::login_sso_complete::post),
        )
        .layer(AndThenLayer::new(
            move |response: axum::response::Response| async move {
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

                Ok::<_, Infallible>(response)
            },
        ))
}

#[must_use]
#[allow(clippy::trait_duplication_in_bounds)]
pub fn router<S, B>(state: Arc<S>) -> Router<S, B>
where
    B: HttpBody + Send + 'static,
    <B as HttpBody>::Data: Send,
    <B as HttpBody>::Error: std::error::Error + Send + Sync,
    S: Send + Sync + 'static,
    Keystore: FromRef<S>,
    UrlBuilder: FromRef<S>,
    Arc<PolicyFactory>: FromRef<S>,
    PgPool: FromRef<S>,
    Encrypter: FromRef<S>,
    Templates: FromRef<S>,
    Mailer: FromRef<S>,
    MatrixHomeserver: FromRef<S>,
{
    let healthcheck_router = healthcheck_router(state.clone());
    let discovery_router = discovery_router(state.clone());
    let api_router = api_router(state.clone());
    let compat_router = compat_router(state.clone());
    let human_router = human_router(state.clone());

    Router::with_state_arc(state)
        .merge(healthcheck_router)
        .merge(discovery_router)
        .merge(human_router)
        .merge(api_router)
        .merge(compat_router)
}

#[cfg(test)]
async fn test_state(pool: PgPool) -> Result<Arc<AppState>, anyhow::Error> {
    use mas_email::MailTransport;

    let url_builder = UrlBuilder::new("https://example.com/".parse()?);

    let templates = Templates::load(None, true, url_builder.clone()).await?;

    // TODO: add test keys to the store
    let key_store = Keystore::default();

    let encrypter = Encrypter::new(&[0x42; 32]);

    let transport = MailTransport::blackhole();
    let mailbox = "server@example.com".parse()?;
    let mailer = Mailer::new(&templates, &transport, &mailbox, &mailbox);

    let homeserver = MatrixHomeserver::new("example.com".to_owned());
    let policy_factory = PolicyFactory::load_default(serde_json::json!({})).await?;
    let policy_factory = Arc::new(policy_factory);

    Ok(Arc::new(AppState {
        pool,
        templates,
        key_store,
        encrypter,
        url_builder,
        mailer,
        homeserver,
        policy_factory,
    }))
}
