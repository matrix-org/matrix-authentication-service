// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use hyper::StatusCode;
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_http::ClientInitError;
use mas_keystore::Encrypter;
use mas_oidc_client::{
    error::{AuthorizationError, DiscoveryError},
    requests::authorization_code::AuthorizationRequestData,
};
use mas_router::UrlBuilder;
use mas_storage::{upstream_oauth2::lookup_provider, LookupResultExt};
use sqlx::PgPool;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Authorization(#[from] AuthorizationError),

    #[error(transparent)]
    InternalError(Box<dyn std::error::Error>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<DiscoveryError> for RouteError {
    fn from(e: DiscoveryError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<mas_storage::upstream_oauth2::ProviderLookupError> for RouteError {
    fn from(e: mas_storage::upstream_oauth2::ProviderLookupError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl From<ClientInitError> for RouteError {
    fn from(e: ClientInitError) -> Self {
        Self::InternalError(Box::new(e))
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::ProviderNotFound => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
            Self::Authorization(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            Self::InternalError(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            Self::Anyhow(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response()
            }
        }
    }
}

pub(crate) async fn get(
    State(http_client_factory): State<HttpClientFactory>,
    State(pool): State<PgPool>,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Path(provider_id): Path<Ulid>,
) -> Result<impl IntoResponse, RouteError> {
    let (clock, mut rng) = crate::rng_and_clock()?;

    let mut txn = pool.begin().await?;

    let provider = lookup_provider(&mut txn, provider_id)
        .await
        .to_option()?
        .ok_or(RouteError::ProviderNotFound)?;

    let http_service = http_client_factory
        .http_service("upstream-discover")
        .await?;

    // First, discover the provider
    let metadata =
        mas_oidc_client::requests::discovery::discover(&http_service, &provider.issuer).await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let data = AuthorizationRequestData {
        client_id: &provider.client_id,
        scope: &provider.scope,
        prompt: None,
        redirect_uri: &redirect_uri,
        code_challenge_methods_supported: metadata.code_challenge_methods_supported.as_deref(),
    };

    // Build an authorization request for it
    let (url, data) = mas_oidc_client::requests::authorization_code::build_authorization_url(
        metadata.authorization_endpoint().clone(),
        data,
        &mut rng,
    )?;

    let session = mas_storage::upstream_oauth2::add_session(
        &mut txn,
        &mut rng,
        &clock,
        &provider,
        data.state,
        data.code_challenge_verifier,
        data.nonce,
    )
    .await?;

    // TODO: handle that cookie somewhere else?
    let mut cookie = Cookie::new("upstream-oauth2-session-id", session.id.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    let cookie_jar = cookie_jar.add(cookie);

    txn.commit().await?;

    Ok((cookie_jar, Redirect::temporary(url.as_str())))
}
