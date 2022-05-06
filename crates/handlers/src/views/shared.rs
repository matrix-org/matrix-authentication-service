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

use axum::response::Redirect;
use mas_data_model::AuthorizationGrant;
use mas_storage::{oauth2::authorization_grant::get_grant_by_id, PostgresqlBackend};
use mas_templates::PostAuthContext;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "next")]
pub(crate) enum PostAuthAction {
    ContinueAuthorizationGrant {
        #[serde(deserialize_with = "serde_with::rust::display_fromstr::deserialize")]
        data: i64,
    },
}

impl PostAuthAction {
    pub fn continue_grant(grant: &AuthorizationGrant<PostgresqlBackend>) -> Self {
        Self::ContinueAuthorizationGrant { data: grant.data }
    }

    pub fn redirect(&self) -> Redirect {
        match self {
            PostAuthAction::ContinueAuthorizationGrant { data } => {
                let url = format!("/authorize/{}", data);
                Redirect::to(&url)
            }
        }
    }

    pub async fn load_context<'e>(
        &self,
        conn: &mut PgConnection,
    ) -> anyhow::Result<PostAuthContext> {
        match self {
            Self::ContinueAuthorizationGrant { data } => {
                let grant = get_grant_by_id(conn, *data).await?;
                let grant = grant.into();
                Ok(PostAuthContext::ContinueAuthorizationGrant { grant })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_post_auth_action() {
        let action: PostAuthAction =
            serde_urlencoded::from_str("next=continue_authorization_grant&data=123").unwrap();

        assert!(matches!(
            action,
            PostAuthAction::ContinueAuthorizationGrant { data: 123 }
        ));
    }
}
