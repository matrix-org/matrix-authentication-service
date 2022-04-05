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

// pub mod authorization;
pub mod discovery;
pub mod introspection;
pub mod keys;
// pub mod token;
pub mod userinfo;

use hyper::{
    http::uri::{Parts, PathAndQuery},
    Uri,
};
use mas_data_model::AuthorizationGrant;
use mas_storage::{oauth2::authorization_grant::get_grant_by_id, PostgresqlBackend};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ContinueAuthorizationGrant {
    data: String,
}

// TEMP
impl ContinueAuthorizationGrant {
    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let qs = serde_urlencoded::to_string(self)?;
        let path_and_query = PathAndQuery::try_from(format!("/oauth2/authorize/step?{}", qs))?;
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    pub async fn fetch_authorization_grant(
        &self,
        conn: &mut PgConnection,
    ) -> anyhow::Result<AuthorizationGrant<PostgresqlBackend>> {
        let data = self.data.parse()?;
        get_grant_by_id(conn, data).await
    }
}
