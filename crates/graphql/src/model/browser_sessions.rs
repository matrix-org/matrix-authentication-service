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

use async_graphql::{Object, ID};
use chrono::{DateTime, Utc};
use mas_storage::PostgresqlBackend;

use super::User;

pub struct BrowserSession(pub mas_data_model::BrowserSession<PostgresqlBackend>);

impl From<mas_data_model::BrowserSession<PostgresqlBackend>> for BrowserSession {
    fn from(v: mas_data_model::BrowserSession<PostgresqlBackend>) -> Self {
        Self(v)
    }
}

#[Object]
impl BrowserSession {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn user(&self) -> User {
        User(self.0.user.clone())
    }

    async fn last_authentication(&self) -> Option<Authentication> {
        self.0.last_authentication.clone().map(Authentication)
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}

pub struct Authentication(pub mas_data_model::Authentication<PostgresqlBackend>);

#[Object]
impl Authentication {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}
