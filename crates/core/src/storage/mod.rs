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

//! Interactions with the database

#![allow(clippy::used_underscore_binding)] // This is needed by sqlx macros

use chrono::{DateTime, Utc};
use mas_data_model::{StorageBackend, StorageBackendMarker};
use serde::Serialize;
use sqlx::migrate::Migrator;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("database query returned an inconsistent state")]
pub struct DatabaseInconsistencyError;

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PostgresqlBackend;

impl StorageBackend for PostgresqlBackend {
    type AccessTokenData = i64;
    type AuthenticationData = i64;
    type AuthorizationCodeData = i64;
    type BrowserSessionData = i64;
    type ClientData = ();
    type RefreshTokenData = i64;
    type SessionData = i64;
    type UserData = i64;
}

impl StorageBackendMarker for PostgresqlBackend {}

struct IdAndCreationTime {
    id: i64,
    created_at: DateTime<Utc>,
}

pub mod oauth2;
pub mod user;

pub use self::user::{login, lookup_active_session, register_user};

/// Embedded migrations, allowing them to run on startup
pub static MIGRATOR: Migrator = sqlx::migrate!();
