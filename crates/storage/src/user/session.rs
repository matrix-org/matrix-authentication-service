// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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
use mas_data_model::{BrowserSession, Password, UpstreamOAuthLink, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, Clock, Pagination};

#[async_trait]
pub trait BrowserSessionRepository: Send + Sync {
    type Error;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
    ) -> Result<BrowserSession, Self::Error>;
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error>;
    async fn list_active_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error>;
    async fn count_active(&mut self, user: &User) -> Result<usize, Self::Error>;

    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        user_password: &Password,
    ) -> Result<BrowserSession, Self::Error>;

    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: BrowserSession,
        upstream_oauth_link: &UpstreamOAuthLink,
    ) -> Result<BrowserSession, Self::Error>;
}
