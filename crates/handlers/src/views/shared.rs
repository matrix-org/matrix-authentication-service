// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use mas_router::{PostAuthAction, Route};
use mas_storage::oauth2::authorization_grant::get_grant_by_id;
use mas_templates::PostAuthContext;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct OptionalPostAuthAction {
    #[serde(flatten)]
    pub post_auth_action: Option<PostAuthAction>,
}

impl OptionalPostAuthAction {
    pub fn go_next(&self) -> axum::response::Redirect {
        self.post_auth_action.as_ref().map_or_else(
            || mas_router::Index.go(),
            mas_router::PostAuthAction::go_next,
        )
    }
    pub async fn load_context<'e>(
        &self,
        conn: &mut PgConnection,
    ) -> anyhow::Result<Option<PostAuthContext>> {
        match &self.post_auth_action {
            Some(PostAuthAction::ContinueAuthorizationGrant { data }) => {
                let grant = get_grant_by_id(conn, *data).await?;
                let grant = grant.into();
                Ok(Some(PostAuthContext::ContinueAuthorizationGrant { grant }))
            }
            None => Ok(None),
        }
    }
}
