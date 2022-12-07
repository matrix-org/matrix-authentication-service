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
use mas_storage::{
    compat::get_compat_sso_login_by_id, oauth2::authorization_grant::get_grant_by_id,
};
use mas_templates::{PostAuthContext, PostAuthContextInner};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct OptionalPostAuthAction {
    #[serde(flatten)]
    pub post_auth_action: Option<PostAuthAction>,
}

impl OptionalPostAuthAction {
    pub fn go_next_or_default<T: Route>(&self, default: &T) -> axum::response::Redirect {
        self.post_auth_action
            .as_ref()
            .map_or_else(|| default.go(), mas_router::PostAuthAction::go_next)
    }

    pub fn go_next(&self) -> axum::response::Redirect {
        self.go_next_or_default(&mas_router::Index)
    }

    pub async fn load_context<'e>(
        &self,
        conn: &mut PgConnection,
    ) -> anyhow::Result<Option<PostAuthContext>> {
        let Some(action) = self.post_auth_action.clone() else { return Ok(None) };
        let ctx = match action {
            PostAuthAction::ContinueAuthorizationGrant { data } => {
                let grant = get_grant_by_id(conn, data).await?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueAuthorizationGrant { grant }
            }

            PostAuthAction::ContinueCompatSsoLogin { data } => {
                let login = get_compat_sso_login_by_id(conn, data).await?;
                let login = Box::new(login);
                PostAuthContextInner::ContinueCompatSsoLogin { login }
            }

            PostAuthAction::ChangePassword => PostAuthContextInner::ChangePassword,

            PostAuthAction::LinkUpstream { id } => {
                let link = mas_storage::upstream_oauth2::lookup_link(&mut *conn, id).await?;

                let provider =
                    mas_storage::upstream_oauth2::lookup_provider(&mut *conn, link.provider_id)
                        .await?;

                let provider = Box::new(provider);
                let link = Box::new(link);
                PostAuthContextInner::LinkUpstream { provider, link }
            }
        };

        Ok(Some(PostAuthContext {
            params: action.clone(),
            ctx,
        }))
    }
}
