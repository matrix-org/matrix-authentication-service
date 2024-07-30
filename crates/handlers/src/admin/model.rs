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

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Serialize;
use ulid::Ulid;

/// A resource, with a type and an ID
pub trait Resource {
    /// The type of the resource
    const KIND: &'static str;

    /// The canonical path prefix for this kind of resource
    const PATH: &'static str;

    /// The ID of the resource
    fn id(&self) -> Ulid;

    /// The canonical path for this resource
    ///
    /// This is the concatenation of the canonical path prefix and the ID
    fn path(&self) -> String {
        format!("{}/{}", Self::PATH, self.id())
    }
}

/// A user
#[derive(Serialize, JsonSchema)]
pub struct User {
    #[serde(skip)]
    id: Ulid,

    /// The username (localpart) of the user
    username: String,

    /// When the user was created
    created_at: DateTime<Utc>,

    /// When the user was locked. If null, the user is not locked.
    locked_at: Option<DateTime<Utc>>,

    /// Whether the user can request admin privileges.
    can_request_admin: bool,
}

impl User {
    /// Samples of users with different properties for examples in the schema
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                can_request_admin: false,
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                username: "bob".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                can_request_admin: true,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                username: "charlie".to_owned(),
                created_at: DateTime::default(),
                locked_at: Some(DateTime::default()),
                can_request_admin: false,
            },
        ]
    }
}

impl From<mas_data_model::User> for User {
    fn from(user: mas_data_model::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            created_at: user.created_at,
            locked_at: user.locked_at,
            can_request_admin: user.can_request_admin,
        }
    }
}

impl Resource for User {
    const KIND: &'static str = "user";
    const PATH: &'static str = "/api/admin/v1/users";

    fn id(&self) -> Ulid {
        self.id
    }
}

/// A OAuth 2.0 session
#[derive(Serialize, JsonSchema)]
pub struct OAuth2Session {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the session was finished
    finished_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns the session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_id: Option<Ulid>,

    /// The ID of the browser session which started this session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_session_id: Option<Ulid>,

    /// The ID of the client which requested this session
    #[schemars(with = "super::schema::Ulid")]
    client_id: Ulid,

    /// The scope granted for this session
    scope: String,

    /// The user agent string of the client which started this session
    user_agent: Option<String>,

    /// The last time the session was active
    last_active_at: Option<DateTime<Utc>>,

    /// The last IP address used by the session
    last_active_ip: Option<IpAddr>,
}

impl From<mas_data_model::Session> for OAuth2Session {
    fn from(session: mas_data_model::Session) -> Self {
        Self {
            id: session.id,
            created_at: session.created_at,
            finished_at: session.finished_at(),
            user_id: session.user_id,
            user_session_id: session.user_session_id,
            client_id: session.client_id,
            scope: session.scope.to_string(),
            user_agent: session.user_agent.map(|ua| ua.raw),
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
        }
    }
}

impl OAuth2Session {
    /// Samples of OAuth 2.0 sessions
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Some(Ulid::from_bytes([0x02; 16])),
                user_session_id: Some(Ulid::from_bytes([0x03; 16])),
                client_id: Ulid::from_bytes([0x04; 16]),
                scope: "openid".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: None,
                user_session_id: None,
                client_id: Ulid::from_bytes([0x05; 16]),
                scope: "urn:mas:admin".to_owned(),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                finished_at: Some(DateTime::default()),
                user_id: Some(Ulid::from_bytes([0x04; 16])),
                user_session_id: Some(Ulid::from_bytes([0x05; 16])),
                client_id: Ulid::from_bytes([0x06; 16]),
                scope: "urn:matrix:org.matrix.msc2967.client:api:*".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
        ]
    }
}

impl Resource for OAuth2Session {
    const KIND: &'static str = "oauth2-session";
    const PATH: &'static str = "/api/admin/v1/oauth2-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}
