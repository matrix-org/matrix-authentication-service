// Copyright 2022 The Matrix.org Foundation C.I.C.
//
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
    extract::{Query, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use mas_router::{CompatLoginSsoAction, CompatLoginSsoComplete, UrlBuilder};
use mas_storage::compat::insert_compat_sso_login;
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use serde_with::serde;
use sqlx::PgPool;
use thiserror::Error;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Params {
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
    action: Option<CompatLoginSsoAction>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("missing redirect_url")]
    MissingRedirectUrl,

    #[error("invalid redirect_url")]
    InvalidRedirectUrl,
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self)).into_response()
    }
}

#[tracing::instrument(skip(pool, url_builder), err)]
pub async fn get(
    State(pool): State<PgPool>,
    State(url_builder): State<UrlBuilder>,
    Query(params): Query<Params>,
) -> Result<impl IntoResponse, RouteError> {
    let (clock, mut rng) = crate::rng_and_clock()?;

    // Check the redirectUrl parameter
    let redirect_url = params.redirect_url.ok_or(RouteError::MissingRedirectUrl)?;
    let redirect_url = Url::parse(&redirect_url).map_err(|_| RouteError::InvalidRedirectUrl)?;

    // Do not allow URLs with username or passwords in them
    if !redirect_url.username().is_empty() || redirect_url.password().is_some() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    // On the http/https scheme, verify the URL has a host
    if matches!(redirect_url.scheme(), "http" | "https") && !redirect_url.has_host() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    let token = Alphanumeric.sample_string(&mut rng, 32);
    let mut conn = pool.acquire().await?;
    let login = insert_compat_sso_login(&mut conn, &mut rng, &clock, token, redirect_url).await?;

    Ok(url_builder.absolute_redirect(&CompatLoginSsoComplete::new(login.data, params.action)))
}
