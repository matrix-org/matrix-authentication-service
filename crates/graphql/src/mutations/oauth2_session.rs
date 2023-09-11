// Copyright 2023 The Matrix.org Foundation C.I.C.
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
use async_graphql::{Context, Description, Enum, InputObject, Object, ID};
use chrono::Duration;
use mas_data_model::{Device, TokenType};
use mas_storage::{
    job::{DeleteDeviceJob, JobRepositoryExt, ProvisionDeviceJob},
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2ClientRepository, OAuth2RefreshTokenRepository,
        OAuth2SessionRepository,
    },
    user::UserRepository,
    RepositoryAccess,
};
use oauth2_types::scope::Scope;

use crate::{
    model::{NodeType, OAuth2Session},
    state::ContextExt,
};

#[derive(Default)]
pub struct OAuth2SessionMutations {
    _private: (),
}

/// The input of the `createOauth2Session` mutation.
#[derive(InputObject)]
pub struct CreateOAuth2SessionInput {
    /// The scope of the session
    scope: String,

    /// The ID of the user for which to create the session
    user_id: ID,

    /// Whether the session should issue a never-expiring access token
    permanent: Option<bool>,
}

/// The payload of the `createOauth2Session` mutation.
#[derive(Description)]
pub struct CreateOAuth2SessionPayload {
    access_token: String,
    refresh_token: Option<String>,
    session: mas_data_model::Session,
}

#[Object(use_type_description)]
impl CreateOAuth2SessionPayload {
    /// Access token for this session
    pub async fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Refresh token for this session, if it is not a permanent session
    pub async fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The OAuth 2.0 session which was just created
    pub async fn oauth2_session(&self) -> OAuth2Session {
        OAuth2Session(self.session.clone())
    }
}

/// The input of the `endOauth2Session` mutation.
#[derive(InputObject)]
pub struct EndOAuth2SessionInput {
    /// The ID of the session to end.
    oauth2_session_id: ID,
}

/// The payload of the `endOauth2Session` mutation.
pub enum EndOAuth2SessionPayload {
    NotFound,
    Ended(mas_data_model::Session),
}

/// The status of the `endOauth2Session` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndOAuth2SessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndOAuth2SessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndOAuth2SessionStatus {
        match self {
            Self::Ended(_) => EndOAuth2SessionStatus::Ended,
            Self::NotFound => EndOAuth2SessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn oauth2_session(&self) -> Option<OAuth2Session> {
        match self {
            Self::Ended(session) => Some(OAuth2Session(session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl OAuth2SessionMutations {
    /// Create a new arbitrary OAuth 2.0 Session.
    ///
    /// Only available for administrators.
    async fn create_oauth2_session(
        &self,
        ctx: &Context<'_>,
        input: CreateOAuth2SessionInput,
    ) -> Result<CreateOAuth2SessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let scope: Scope = input.scope.parse().context("Invalid scope")?;
        let permanent = input.permanent.unwrap_or(false);
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let session = requester
            .oauth2_session()
            .context("Requester should be a OAuth 2.0 client")?;

        let mut repo = state.repository().await?;
        let clock = state.clock();
        let mut rng = state.rng();

        let client = repo
            .oauth2_client()
            .lookup(session.client_id)
            .await?
            .context("Client not found")?;

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        // Generate a new access token
        let access_token = TokenType::AccessToken.generate(&mut rng);

        // Create the OAuth 2.0 Session
        let session = repo
            .oauth2_session()
            .add(&mut rng, &clock, &client, Some(&user), None, scope)
            .await?;

        // Look for devices to provision
        for scope in &*session.scope {
            if let Some(device) = Device::from_scope_token(scope) {
                repo.job()
                    .schedule_job(ProvisionDeviceJob::new(&user, &device))
                    .await?;
            }
        }

        let ttl = if permanent {
            // XXX: that's lazy
            Duration::days(365 * 50)
        } else {
            Duration::minutes(5)
        };
        let access_token = repo
            .oauth2_access_token()
            .add(&mut rng, &clock, &session, access_token, ttl)
            .await?;

        let refresh_token = if !permanent {
            let refresh_token = TokenType::RefreshToken.generate(&mut rng);

            let refresh_token = repo
                .oauth2_refresh_token()
                .add(&mut rng, &clock, &session, &access_token, refresh_token)
                .await?;

            Some(refresh_token)
        } else {
            None
        };

        Ok(CreateOAuth2SessionPayload {
            session,
            access_token: access_token.access_token,
            refresh_token: refresh_token.map(|t| t.refresh_token),
        })
    }

    async fn end_oauth2_session(
        &self,
        ctx: &Context<'_>,
        input: EndOAuth2SessionInput,
    ) -> Result<EndOAuth2SessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let oauth2_session_id = NodeType::OAuth2Session.extract_ulid(&input.oauth2_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let clock = state.clock();

        let session = repo.oauth2_session().lookup(oauth2_session_id).await?;
        let Some(session) = session else {
            return Ok(EndOAuth2SessionPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(EndOAuth2SessionPayload::NotFound);
        }

        if let Some(user_id) = session.user_id {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .context("Could not load user")?;

            // Scan the scopes of the session to find if there is any device that should be
            // deleted from the Matrix server.
            // TODO: this should be moved in a higher level "end oauth session" method.
            // XXX: this might not be the right semantic, but it's the best we
            // can do for now, since we're not explicitly storing devices for OAuth2
            // sessions.
            for scope in &*session.scope {
                if let Some(device) = Device::from_scope_token(scope) {
                    // Schedule a job to delete the device.
                    repo.job()
                        .schedule_job(DeleteDeviceJob::new(&user, &device))
                        .await?;
                }
            }
        }

        let session = repo.oauth2_session().finish(&clock, session).await?;

        repo.save().await?;

        Ok(EndOAuth2SessionPayload::Ended(session))
    }
}
