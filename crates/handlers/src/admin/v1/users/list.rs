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
use axum::{
    extract::{rejection::QueryRejection, Query},
    response::IntoResponse,
    Json,
};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_storage::{user::UserFilter, Page};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, User},
        params::Pagination,
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    /// The user is active
    Active,

    /// The user is locked
    Locked,
}

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    #[serde(rename = "filter[can_request_admin]")]
    can_request_admin: Option<bool>,

    #[serde(rename = "filter[status]")]
    status: Option<UserStatus>,
}

impl<'a> From<&'a FilterParams> for UserFilter<'a> {
    fn from(val: &'a FilterParams) -> Self {
        let filter = UserFilter::default();

        let filter = match val.can_request_admin {
            Some(true) => filter.can_request_admin_only(),
            Some(false) => filter.cannot_request_admin_only(),
            None => filter,
        };

        let filter = match val.status {
            Some(UserStatus::Active) => filter.active_only(),
            Some(UserStatus::Locked) => filter.locked_only(),
            None => filter,
        };

        filter
    }
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Invalid filter parameters")]
    InvalidFilter(#[from] QueryRejection),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };
        (status, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .summary("List users")
        .tag("user")
        .response_with::<200, Json<PaginatedResponse<User>>, _>(|t| {
            let users = User::samples();
            let pagination = mas_storage::Pagination::first(users.len());
            let page = Page {
                edges: users.into(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of users")
                .example(PaginatedResponse::new(page, pagination, 42, User::PATH))
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.list", skip_all, err)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination): Pagination,
    filter: FilterParams,
) -> Result<Json<PaginatedResponse<User>>, RouteError> {
    let filter = UserFilter::from(&filter);

    let page = repo.user().list(filter, pagination).await?;
    let count = repo.user().count(filter).await?;

    Ok(Json(PaginatedResponse::new(
        page.map(User::from),
        pagination,
        count,
        User::PATH,
    )))
}
