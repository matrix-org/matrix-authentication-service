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

// Generated code from schemars violates this rule
#![allow(clippy::str_to_string)]

use std::num::NonZeroUsize;

use aide::OperationIo;
use async_trait::async_trait;
use axum::{
    extract::{
        rejection::{PathRejection, QueryRejection},
        FromRequestParts, Path, Query,
    },
    response::IntoResponse,
    Json,
};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_storage::pagination::PaginationDirection;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use super::response::ErrorResponse;

#[derive(Debug, thiserror::Error)]
#[error("Invalid ULID in path")]
pub struct UlidPathParamRejection(#[from] PathRejection);

impl IntoResponse for UlidPathParamRejection {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::from_error(&self)),
        )
            .into_response()
    }
}

#[derive(JsonSchema, Debug, Clone, Copy, Deserialize)]
struct UlidInPath {
    #[schemars(
        with = "String",
        title = "ULID",
        description = "A ULID as per https://github.com/ulid/spec",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$")
    )]
    id: Ulid,
}

#[derive(FromRequestParts, OperationIo, Debug, Clone, Copy)]
#[from_request(rejection(UlidPathParamRejection))]
#[aide(input_with = "Path<UlidInPath>")]
pub struct UlidPathParam(#[from_request(via(Path))] UlidInPath);

impl std::ops::Deref for UlidPathParam {
    type Target = Ulid;

    fn deref(&self) -> &Self::Target {
        &self.0.id
    }
}

/// The default page size if not specified
const DEFAULT_PAGE_SIZE: usize = 10;

#[derive(Deserialize, JsonSchema, Clone, Copy)]
struct PaginationParams {
    /// Retrieve the items before the given ID
    #[serde(rename = "page[before]")]
    #[schemars(with = "Option<String>")]
    before: Option<Ulid>,

    /// Retrieve the items after the given ID
    #[serde(rename = "page[after]")]
    #[schemars(with = "Option<String>")]
    after: Option<Ulid>,

    /// Retrieve the first N items
    #[serde(rename = "page[first]")]
    first: Option<NonZeroUsize>,

    /// Retrieve the last N items
    #[serde(rename = "page[last]")]
    last: Option<NonZeroUsize>,
}

#[derive(Debug, thiserror::Error)]
pub enum PaginationRejection {
    #[error("Invalid pagination parameters")]
    Invalid(#[from] QueryRejection),

    #[error("Cannot specify both `page[first]` and `page[last]` parameters")]
    FirstAndLast,
}

impl IntoResponse for PaginationRejection {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::from_error(&self)),
        )
            .into_response()
    }
}

/// An extractor for pagination parameters in the query string
#[derive(OperationIo, Debug, Clone, Copy)]
#[aide(input_with = "Query<PaginationParams>")]
pub struct Pagination(pub mas_storage::Pagination);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Pagination {
    type Rejection = PaginationRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let params = Query::<PaginationParams>::from_request_parts(parts, state).await?;

        // Figure out the direction and the count out of the first and last parameters
        let (direction, count) = match (params.first, params.last) {
            // Make sure we don't specify both first and last
            (Some(_), Some(_)) => return Err(PaginationRejection::FirstAndLast),

            // Default to forward pagination with a default page size
            (None, None) => (PaginationDirection::Forward, DEFAULT_PAGE_SIZE),

            (Some(first), None) => (PaginationDirection::Forward, first.into()),
            (None, Some(last)) => (PaginationDirection::Backward, last.into()),
        };

        Ok(Self(mas_storage::Pagination {
            before: params.before,
            after: params.after,
            direction,
            count,
        }))
    }
}
