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

#![deny(clippy::future_not_send)]
#![allow(clippy::module_name_repetitions)]

pub mod client_authorization;
pub mod cookies;
pub mod csrf;
pub mod error_wrapper;
pub mod fancy_error;
pub mod http_client_factory;
pub mod jwt;
pub mod language_detection;
pub mod sentry;
pub mod session;
pub mod user_authorization;

pub use axum;

pub use self::{
    error_wrapper::ErrorWrapper,
    fancy_error::FancyError,
    session::{SessionInfo, SessionInfoExt},
};
