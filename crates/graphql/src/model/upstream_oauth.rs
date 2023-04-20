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
use async_graphql::{Context, Object, ID};
use chrono::{DateTime, Utc};
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, user::UserRepository};

use super::{NodeType, User};
use crate::state::ContextExt;

#[derive(Debug, Clone)]
pub struct UpstreamOAuth2Provider {
    provider: mas_data_model::UpstreamOAuthProvider,
}

impl UpstreamOAuth2Provider {
    #[must_use]
    pub const fn new(provider: mas_data_model::UpstreamOAuthProvider) -> Self {
        Self { provider }
    }
}

#[Object]
impl UpstreamOAuth2Provider {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UpstreamOAuth2Provider.id(self.provider.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.provider.created_at
    }

    /// OpenID Connect issuer URL.
    pub async fn issuer(&self) -> &str {
        &self.provider.issuer
    }

    /// Client ID used for this provider.
    pub async fn client_id(&self) -> &str {
        &self.provider.client_id
    }
}

impl UpstreamOAuth2Link {
    #[must_use]
    pub const fn new(link: mas_data_model::UpstreamOAuthLink) -> Self {
        Self {
            link,
            provider: None,
            user: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamOAuth2Link {
    link: mas_data_model::UpstreamOAuthLink,
    provider: Option<mas_data_model::UpstreamOAuthProvider>,
    user: Option<mas_data_model::User>,
}

#[Object]
impl UpstreamOAuth2Link {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UpstreamOAuth2Link.id(self.link.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.link.created_at
    }

    /// Subject used for linking
    pub async fn subject(&self) -> &str {
        &self.link.subject
    }

    /// The provider for which this link is.
    pub async fn provider(
        &self,
        ctx: &Context<'_>,
    ) -> Result<UpstreamOAuth2Provider, async_graphql::Error> {
        let state = ctx.state();
        let provider = if let Some(provider) = &self.provider {
            // Cached
            provider.clone()
        } else {
            // Fetch on-the-fly
            let mut repo = state.repository().await?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(self.link.provider_id)
                .await?
                .context("Upstream OAuth 2.0 provider not found")?;
            repo.cancel().await?;

            provider
        };

        Ok(UpstreamOAuth2Provider::new(provider))
    }

    /// The user to which this link is associated.
    pub async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let user = if let Some(user) = &self.user {
            // Cached
            user.clone()
        } else if let Some(user_id) = &self.link.user_id {
            // Fetch on-the-fly
            let mut repo = state.repository().await?;

            let user = repo
                .user()
                .lookup(*user_id)
                .await?
                .context("User not found")?;
            repo.cancel().await?;

            user
        } else {
            return Ok(None);
        };

        Ok(Some(User(user)))
    }
}
