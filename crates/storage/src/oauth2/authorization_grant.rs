// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

use std::num::NonZeroU32;

use async_trait::async_trait;
use mas_data_model::{AuthorizationCode, AuthorizationGrant, Client, Session};
use oauth2_types::{requests::ResponseMode, scope::Scope};
use rand::RngCore;
use ulid::Ulid;
use url::Url;

use crate::Clock;

#[async_trait]
pub trait OAuth2AuthorizationGrantRepository: Send + Sync {
    type Error;

    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        redirect_uri: Url,
        scope: Scope,
        code: Option<AuthorizationCode>,
        state: Option<String>,
        nonce: Option<String>,
        max_age: Option<NonZeroU32>,
        response_mode: ResponseMode,
        response_type_id_token: bool,
        requires_consent: bool,
    ) -> Result<AuthorizationGrant, Self::Error>;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<AuthorizationGrant>, Self::Error>;

    async fn find_by_code(&mut self, code: &str)
        -> Result<Option<AuthorizationGrant>, Self::Error>;

    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        session: &Session,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;

    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;

    async fn give_consent(
        &mut self,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;
}
