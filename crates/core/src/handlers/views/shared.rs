// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use hyper::Uri;
use mas_data_model::StorageBackend;
use mas_templates::PostAuthContext;
use serde::{Deserialize, Serialize};
use sqlx::PgExecutor;

use super::super::oauth2::ContinueAuthorizationGrant;
use crate::storage::PostgresqlBackend;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "next")]
pub(crate) enum PostAuthAction<S: StorageBackend> {
    #[serde(bound(
        deserialize = "S::AuthorizationGrantData: std::str::FromStr, 
                       <S::AuthorizationGrantData as std::str::FromStr>::Err: std::fmt::Display",
        serialize = "S::AuthorizationGrantData: std::fmt::Display"
    ))]
    ContinueAuthorizationGrant(ContinueAuthorizationGrant<S>),
}

impl<S: StorageBackend> PostAuthAction<S> {
    pub fn build_uri(&self) -> anyhow::Result<Uri>
    where
        S::AuthorizationGrantData: std::fmt::Display,
    {
        match self {
            PostAuthAction::ContinueAuthorizationGrant(c) => c.build_uri(),
        }
    }
}

impl<S: StorageBackend> From<ContinueAuthorizationGrant<S>> for PostAuthAction<S> {
    fn from(g: ContinueAuthorizationGrant<S>) -> Self {
        Self::ContinueAuthorizationGrant(g)
    }
}

impl PostAuthAction<PostgresqlBackend> {
    pub async fn load_context<'e>(
        &self,
        executor: impl PgExecutor<'e>,
    ) -> anyhow::Result<PostAuthContext> {
        match self {
            Self::ContinueAuthorizationGrant(c) => {
                let grant = c.fetch_authorization_grant(executor).await?;
                let grant = grant.into();
                Ok(PostAuthContext::ContinueAuthorizationGrant { grant })
            }
        }
    }
}
