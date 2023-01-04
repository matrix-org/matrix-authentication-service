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

use anyhow::Context as _;
use async_graphql::{Context, Description, Object, ID};
use chrono::{DateTime, Utc};
use mas_data_model::CompatSsoLoginState;
use mas_storage::{user::UserRepository, Repository};
use sqlx::PgPool;
use url::Url;

use super::{NodeType, User};

/// A compat session represents a client session which used the legacy Matrix
/// login API.
#[derive(Description)]
pub struct CompatSession(pub mas_data_model::CompatSession);

#[Object(use_type_description)]
impl CompatSession {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::CompatSession.id(self.0.id)
    }

    /// The user authorized for this session.
    async fn user(&self, ctx: &Context<'_>) -> Result<User, async_graphql::Error> {
        let mut conn = ctx.data::<PgPool>()?.acquire().await?;
        let user = conn
            .user()
            .lookup(self.0.user_id)
            .await?
            .context("Could not load user")?;
        Ok(User(user))
    }

    /// The Matrix Device ID of this session.
    async fn device_id(&self) -> &str {
        self.0.device.as_str()
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the session ended.
    pub async fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.0.finished_at
    }
}

/// A compat SSO login represents a login done through the legacy Matrix login
/// API, via the `m.login.sso` login method.
#[derive(Description)]
pub struct CompatSsoLogin(pub mas_data_model::CompatSsoLogin);

#[Object(use_type_description)]
impl CompatSsoLogin {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::CompatSsoLogin.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// The redirect URI used during the login.
    async fn redirect_uri(&self) -> &Url {
        &self.0.redirect_uri
    }

    /// When the login was fulfilled, and the user was redirected back to the
    /// client.
    async fn fulfilled_at(&self) -> Option<DateTime<Utc>> {
        match &self.0.state {
            CompatSsoLoginState::Pending => None,
            CompatSsoLoginState::Fulfilled { fulfilled_at, .. }
            | CompatSsoLoginState::Exchanged { fulfilled_at, .. } => Some(*fulfilled_at),
        }
    }

    /// When the client exchanged the login token sent during the redirection.
    async fn exchanged_at(&self) -> Option<DateTime<Utc>> {
        match &self.0.state {
            CompatSsoLoginState::Pending | CompatSsoLoginState::Fulfilled { .. } => None,
            CompatSsoLoginState::Exchanged { exchanged_at, .. } => Some(*exchanged_at),
        }
    }

    /// The compat session which was started by this login.
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
