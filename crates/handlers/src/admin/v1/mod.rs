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

use aide::axum::{
    routing::{get_with, post_with},
    ApiRouter,
};
use axum::extract::{FromRef, FromRequestParts};
use mas_matrix::BoxHomeserverConnection;
use mas_storage::BoxRng;

use super::call_context::CallContext;
use crate::passwords::PasswordManager;

mod oauth2_sessions;
mod users;

pub fn router<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    BoxHomeserverConnection: FromRef<S>,
    PasswordManager: FromRef<S>,
    BoxRng: FromRequestParts<S>,
    CallContext: FromRequestParts<S>,
{
    ApiRouter::<S>::new()
        .api_route(
            "/oauth2-sessions",
            get_with(self::oauth2_sessions::list, self::oauth2_sessions::list_doc),
        )
        .api_route(
            "/oauth2-sessions/:id",
            get_with(self::oauth2_sessions::get, self::oauth2_sessions::get_doc),
        )
        .api_route(
            "/users",
            get_with(self::users::list, self::users::list_doc)
                .post_with(self::users::add, self::users::add_doc),
        )
        .api_route(
            "/users/:id",
            get_with(self::users::get, self::users::get_doc),
        )
        .api_route(
            "/users/:id/set-password",
            post_with(self::users::set_password, self::users::set_password_doc),
        )
        .api_route(
            "/users/by-username/:username",
            get_with(self::users::by_username, self::users::by_username_doc),
        )
        .api_route(
            "/users/:id/deactivate",
            post_with(self::users::deactivate, self::users::deactivate_doc),
        )
        .api_route(
            "/users/:id/lock",
            post_with(self::users::lock, self::users::lock_doc),
        )
        .api_route(
            "/users/:id/unlock",
            post_with(self::users::unlock, self::users::unlock_doc),
        )
}
