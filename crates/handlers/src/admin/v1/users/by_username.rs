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
use axum::{extract::Path, response::IntoResponse, Json};
use hyper::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::User,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User with username {0:?} not found")]
    NotFound(String),
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

#[derive(Deserialize, JsonSchema)]
pub struct UsernamePathParam {
    /// The username (localpart) of the user to get
    username: String,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .summary("Get a user by its username (localpart)")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            let [sample, ..] = User::samples();
            let response =
                SingleResponse::new(sample, "/api/admin/v1/users/by-username/alice".to_owned());
            t.description("User was found").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound("alice".to_owned()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.by_username", skip_all, err)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Path(UsernamePathParam { username }): Path<UsernamePathParam>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let self_path = format!("/api/admin/v1/users/by-username/{username}");
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .ok_or(RouteError::NotFound(username))?;

    Ok(Json(SingleResponse::new(User::from(user), self_path)))
}
