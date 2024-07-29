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

use aide::{transform::TransformOperation, NoApi, OperationIo};
use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_matrix::BoxHomeserverConnection;
use mas_storage::{
    job::{JobRepositoryExt, ProvisionUserJob},
    BoxRng,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::warn;

use crate::{
    admin::{
        call_context::CallContext,
        model::User,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

// XXX: this should be shared with the graphql handler
fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Homeserver(anyhow::Error),

    #[error("Username is not valid")]
    UsernameNotValid,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Username is reserved by the homeserver")]
    UsernameReserved,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let status = match self {
            Self::Internal(_) | Self::Homeserver(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UsernameNotValid => StatusCode::BAD_REQUEST,
            Self::UserAlreadyExists | Self::UsernameReserved => StatusCode::CONFLICT,
        };
        (status, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/users` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRequest")]
pub struct Request {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is available.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in MAS to craft special
    /// tokens (like with admin access) for them
    #[serde(default)]
    skip_homeserver_check: bool,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .summary("Create a new user")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            let [sample, ..] = User::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User was created").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UsernameNotValid);
            t.description("Username is not valid").example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserAlreadyExists);
            t.description("User already exists").example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UsernameReserved);
            t.description("Username is reserved by the homeserver")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.add", skip_all, err)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    State(homeserver): State<BoxHomeserverConnection>,
    Json(params): Json<Request>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    if repo.user().exists(&params.username).await? {
        return Err(RouteError::UserAlreadyExists);
    }

    // Do some basic check on the username
    if !username_valid(&params.username) {
        return Err(RouteError::UsernameNotValid);
    }

    // Ask the homeserver if the username is available
    let homeserver_available = homeserver
        .is_localpart_available(&params.username)
        .await
        .map_err(RouteError::Homeserver)?;

    if !homeserver_available {
        if !params.skip_homeserver_check {
            return Err(RouteError::UsernameReserved);
        }

        // If we skipped the check, we still want to shout about it
        warn!("Skipped homeserver check for username {}", params.username);
    }

    let user = repo.user().add(&mut rng, &clock, params.username).await?;

    repo.job()
        .schedule_job(ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}
