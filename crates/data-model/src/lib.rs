// Copyright 2021 The Matrix.org Foundation C.I.C.
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

#![forbid(unsafe_code)]
#![deny(clippy::all, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::trait_duplication_in_bounds
)]

pub mod errors;
pub(crate) mod oauth2;
pub(crate) mod tokens;
pub(crate) mod traits;
pub(crate) mod users;

pub use self::{
    oauth2::{
        AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, Pkce, Session,
    },
    tokens::{AccessToken, RefreshToken, TokenFormatError, TokenType},
    traits::{StorageBackend, StorageBackendMarker},
    users::{
        Authentication, BrowserSession, User, UserEmail, UserEmailVerification,
        UserEmailVerificationState,
    },
};
