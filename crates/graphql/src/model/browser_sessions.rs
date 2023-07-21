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

use async_graphql::{Context, Description, Enum, Object, ID};
use chrono::{DateTime, Utc};
use mas_storage::{user::BrowserSessionRepository, RepositoryAccess};

use super::{NodeType, User};
use crate::state::ContextExt;

/// The state of a browser session.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum BrowserSessionState {
    /// The session is active.
    Active,

    /// The session is no longer active.
    Finished,
}

/// A browser session represents a logged in user in a browser.
#[derive(Description)]
pub struct BrowserSession(pub mas_data_model::BrowserSession);

impl From<mas_data_model::BrowserSession> for BrowserSession {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v)
    }
}

#[Object(use_type_description)]
impl BrowserSession {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::BrowserSession.id(self.0.id)
    }

    /// The user logged in this session.
    async fn user(&self) -> User {
        User(self.0.user.clone())
    }

    /// The most recent authentication of this session.
    async fn last_authentication(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<Authentication>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&self.0)
            .await?;

        repo.cancel().await?;

        Ok(last_authentication.map(Authentication))
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}

/// An authentication records when a user enter their credential in a browser
/// session.
#[derive(Description)]
pub struct Authentication(pub mas_data_model::Authentication);

#[Object(use_type_description)]
impl Authentication {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::Authentication.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}
