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

use axum::{response::IntoResponse, Extension, Json};
use hyper::StatusCode;
use mas_storage::oauth2::client::insert_client;
use oauth2_types::{
    errors::SERVER_ERROR,
    registration::{ClientMetadata, ClientRegistrationResponse},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sqlx::PgPool;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl From<sqlx::Error> for RouteError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(SERVER_ERROR)).into_response()
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn post(
    Extension(pool): Extension<PgPool>,
    Json(body): Json<ClientMetadata>,
) -> Result<impl IntoResponse, RouteError> {
    info!(?body, "Client registration");

    // Grab a txn
    let mut txn = pool.begin().await?;

    // Let's generate a random client ID
    let client_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    insert_client(
        &mut txn,
        &client_id,
        &body.redirect_uris,
        None,
        &body.response_types,
        &body.grant_types,
        &body.contacts,
        body.client_name.as_deref(),
        body.logo_uri.as_ref(),
        body.client_uri.as_ref(),
        body.policy_uri.as_ref(),
        body.tos_uri.as_ref(),
        body.jwks_uri.as_ref(),
        body.jwks.as_ref(),
        body.id_token_signed_response_alg,
        body.token_endpoint_auth_method,
        body.token_endpoint_auth_signing_alg,
        body.initiate_login_uri.as_ref(),
    )
    .await?;

    txn.commit().await?;

    let response = ClientRegistrationResponse {
        client_id,
        client_secret: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
    };

    Ok((StatusCode::CREATED, Json(response)))
}
