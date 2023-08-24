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
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect},
};
use hyper::StatusCode;
use mas_axum_utils::{cookies::CookieJar, http_client_factory::HttpClientFactory};
use mas_oidc_client::requests::authorization_code::AuthorizationRequestData;
use mas_router::UrlBuilder;
use mas_storage::{
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
    BoxClock, BoxRepository, BoxRng,
};
use thiserror::Error;
use ulid::Ulid;

use super::UpstreamSessionsCookie;
use crate::{impl_from_error_for_route, views::shared::OptionalPostAuthAction};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_http::ClientInitError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::AuthorizationError);
impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        sentry::capture_error(&self);
        match self {
            Self::ProviderNotFound => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.authorize.get",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    Query(query): Query<OptionalPostAuthAction>,
) -> Result<impl IntoResponse, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .ok_or(RouteError::ProviderNotFound)?;

    let http_service = http_client_factory.http_service().await?;

    // First, discover the provider
    let metadata =
        mas_oidc_client::requests::discovery::discover(&http_service, &provider.issuer).await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let mut data = AuthorizationRequestData::new(
        provider.client_id.clone(),
        provider.scope.clone(),
        redirect_uri,
    );

    if let Some(methods) = metadata.code_challenge_methods_supported.clone() {
        data = data.with_code_challenge_methods_supported(methods);
    }

    // Build an authorization request for it
    let (url, data) = mas_oidc_client::requests::authorization_code::build_authorization_url(
        metadata.authorization_endpoint().clone(),
        data,
        &mut rng,
    )?;

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &clock,
            &provider,
            data.state.clone(),
            data.code_challenge_verifier,
            data.nonce,
        )
        .await?;

    let cookie_jar = UpstreamSessionsCookie::load(&cookie_jar)
        .add(session.id, provider.id, data.state, query.post_auth_action)
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((cookie_jar, Redirect::temporary(url.as_str())))
}
