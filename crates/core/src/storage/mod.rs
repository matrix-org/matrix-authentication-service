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

#![allow(clippy::used_underscore_binding)] // This is needed by sqlx macros

use sqlx::migrate::Migrator;

pub mod oauth2;
pub mod user;

pub use self::user::{login, lookup_active_session, register_user, SessionInfo, User};

pub static MIGRATOR: Migrator = sqlx::migrate!();
