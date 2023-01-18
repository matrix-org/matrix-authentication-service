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

use async_trait::async_trait;
use mas_data_model::{CompatSession, CompatSsoLogin, User};
use rand::RngCore;
use ulid::Ulid;
use url::Url;

use crate::{pagination::Page, Clock, Pagination};

#[async_trait]
pub trait CompatSsoLoginRepository: Send + Sync {
    type Error;

    /// Lookup a compat SSO login by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSsoLogin>, Self::Error>;

    /// Find a compat SSO login by its login token
    async fn find_by_token(
        &mut self,
        login_token: &str,
    ) -> Result<Option<CompatSsoLogin>, Self::Error>;

    /// Start a new compat SSO login token
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        login_token: String,
        redirect_uri: Url,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// Fulfill a compat SSO login by providing a compat session
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        compat_session: &CompatSession,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// Mark a compat SSO login as exchanged
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
    ) -> Result<CompatSsoLogin, Self::Error>;

    /// Get a paginated list of compat SSO logins for a user
    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<CompatSsoLogin>, Self::Error>;
}
