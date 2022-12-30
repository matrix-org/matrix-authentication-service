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

use sqlx::{PgConnection, Postgres, Transaction};

use crate::upstream_oauth2::PgUpstreamOAuthLinkRepository;

pub trait Repository {
    type UpstreamOAuthLinkRepository<'c>
    where
        Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_>;
}

impl Repository for PgConnection {
    type UpstreamOAuthLinkRepository<'c> = PgUpstreamOAuthLinkRepository<'c> where Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_> {
        PgUpstreamOAuthLinkRepository::new(self)
    }
}

impl<'t> Repository for Transaction<'t, Postgres> {
    type UpstreamOAuthLinkRepository<'c> = PgUpstreamOAuthLinkRepository<'c> where Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_> {
        PgUpstreamOAuthLinkRepository::new(self)
    }
}
