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
