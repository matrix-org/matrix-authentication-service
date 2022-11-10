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

use async_graphql::{Interface, ID};
use chrono::{DateTime, Utc};

mod browser_sessions;
mod compat_sessions;
mod cursor;
mod oauth;
mod users;

pub use self::{
    browser_sessions::{Authentication, BrowserSession},
    compat_sessions::{CompatSession, CompatSsoLogin},
    cursor::{Cursor, NodeCursor, NodeType},
    oauth::{OAuth2Client, OAuth2Consent, OAuth2Session},
    users::{User, UserEmail},
};

/// An object with an ID.
#[derive(Interface)]
#[graphql(field(name = "id", desc = "ID of the object.", type = "ID"))]
pub enum Node {
    Authentication(Box<Authentication>),
    BrowserSession(Box<BrowserSession>),
    CompatSession(Box<CompatSession>),
    CompatSsoLogin(Box<CompatSsoLogin>),
    OAuth2Client(Box<OAuth2Client>),
    OAuth2Session(Box<OAuth2Session>),
    User(Box<User>),
    UserEmail(Box<UserEmail>),
}

#[derive(Interface)]
#[graphql(field(
    name = "created_at",
    desc = "When the object was created.",
    type = "DateTime<Utc>"
))]
pub enum CreationEvent {
    Authentication(Box<Authentication>),
    CompatSession(Box<CompatSession>),
    BrowserSession(Box<BrowserSession>),
    UserEmail(Box<UserEmail>),
}
