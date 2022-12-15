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

use async_graphql::Interface;
use chrono::{DateTime, Utc};

mod browser_sessions;
mod compat_sessions;
mod cursor;
mod node;
mod oauth;
mod upstream_oauth;
mod users;

pub use self::{
    browser_sessions::{Authentication, BrowserSession},
    compat_sessions::{CompatSession, CompatSsoLogin},
    cursor::{Cursor, NodeCursor},
    node::{Node, NodeType},
    oauth::{OAuth2Client, OAuth2Consent, OAuth2Session},
    upstream_oauth::{UpstreamOAuth2Link, UpstreamOAuth2Provider},
    users::{User, UserEmail},
};

/// An object with a creation date.
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
    UpstreamOAuth2Provider(Box<UpstreamOAuth2Provider>),
    UpstreamOAuth2Link(Box<UpstreamOAuth2Link>),
}
