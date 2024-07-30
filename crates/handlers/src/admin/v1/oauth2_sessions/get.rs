// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use aide::{transform::TransformOperation, OperationIo};
use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::OAuth2Session,
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("OAuth 2.0 session ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("getOAuth2Session")
        .summary("Get an OAuth 2.0 session")
        .tag("oauth2-session")
        .response_with::<200, Json<SingleResponse<OAuth2Session>>, _>(|t| {
            let [sample, ..] = OAuth2Session::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("OAuth 2.0 session was found")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("OAuth 2.0 session was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_session.get", skip_all, err)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<OAuth2Session>>, RouteError> {
    let session = repo
        .oauth2_session()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    Ok(Json(SingleResponse::new_canonical(OAuth2Session::from(
        session,
    ))))
}
