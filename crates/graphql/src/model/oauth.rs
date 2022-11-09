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

use async_graphql::{Context, Object, ID};
use mas_storage::{oauth2::client::lookup_client, PostgresqlBackend};
use oauth2_types::scope::Scope;
use sqlx::PgPool;
use ulid::Ulid;
use url::Url;

use super::{BrowserSession, User};

pub struct OAuth2Session(pub mas_data_model::Session<PostgresqlBackend>);

#[Object]
impl OAuth2Session {
    pub async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    pub async fn client(&self) -> OAuth2Client {
        OAuth2Client(self.0.client.clone())
    }

    pub async fn scope(&self) -> String {
        self.0.scope.to_string()
    }

    pub async fn browser_session(&self) -> BrowserSession {
        BrowserSession(self.0.browser_session.clone())
    }

    pub async fn user(&self) -> User {
        User(self.0.browser_session.user.clone())
    }
}

pub struct OAuth2Client(pub mas_data_model::Client<PostgresqlBackend>);

#[Object]
impl OAuth2Client {
    pub async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    pub async fn client_id(&self) -> &str {
        &self.0.client_id
    }

    pub async fn client_name(&self) -> Option<&str> {
        self.0.client_name.as_deref()
    }

    pub async fn client_uri(&self) -> Option<&Url> {
        self.0.client_uri.as_ref()
    }

    pub async fn tos_uri(&self) -> Option<&Url> {
        self.0.tos_uri.as_ref()
    }

    pub async fn policy_uri(&self) -> Option<&Url> {
        self.0.policy_uri.as_ref()
    }

    pub async fn redirect_uris(&self) -> &[Url] {
        &self.0.redirect_uris
    }
}

pub struct OAuth2Consent {
    scope: Scope,
    client_id: Ulid,
}

#[Object]
impl OAuth2Consent {
    pub async fn scope(&self) -> String {
        self.scope.to_string()
    }

    pub async fn client(&self, ctx: &Context<'_>) -> Result<OAuth2Client, async_graphql::Error> {
        let mut conn = ctx.data::<PgPool>()?.acquire().await?;
        let client = lookup_client(&mut conn, self.client_id).await?;
        Ok(OAuth2Client(client))
    }
}
