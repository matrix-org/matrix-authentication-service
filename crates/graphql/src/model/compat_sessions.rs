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
use mas_data_model::CompatSsoLoginState;
use mas_storage::PostgresqlBackend;
use url::Url;

use super::User;

pub struct CompatSession(pub mas_data_model::CompatSession<PostgresqlBackend>);

#[Object]
impl CompatSession {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn user(&self) -> User {
        User(self.0.user.clone())
    }

    async fn device_id(&self) -> &str {
        self.0.device.as_str()
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    async fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.0.finished_at
    }
}

pub struct CompatSsoLogin(pub mas_data_model::CompatSsoLogin<PostgresqlBackend>);

#[Object]
impl CompatSsoLogin {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    async fn redirect_uri(&self) -> &Url {
        &self.0.redirect_uri
    }

    async fn fulfilled_at(&self) -> Option<DateTime<Utc>> {
        match &self.0.state {
            CompatSsoLoginState::Pending => None,
            CompatSsoLoginState::Fulfilled { fulfilled_at, .. }
            | CompatSsoLoginState::Exchanged { fulfilled_at, .. } => Some(*fulfilled_at),
        }
    }

    async fn exchanged_at(&self) -> Option<DateTime<Utc>> {
        match &self.0.state {
            CompatSsoLoginState::Pending | CompatSsoLoginState::Fulfilled { .. } => None,
            CompatSsoLoginState::Exchanged { exchanged_at, .. } => Some(*exchanged_at),
        }
    }

    async fn session(&self) -> Option<CompatSession> {
        match &self.0.state {
            CompatSsoLoginState::Pending => None,
            CompatSsoLoginState::Fulfilled { session, .. }
            | CompatSsoLoginState::Exchanged { session, .. } => {
                Some(CompatSession(session.clone()))
            }
        }
    }
}
