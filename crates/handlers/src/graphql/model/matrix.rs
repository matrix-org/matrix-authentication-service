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

use async_graphql::SimpleObject;
use mas_matrix::HomeserverConnection;

#[derive(SimpleObject)]
pub struct MatrixUser {
    /// The Matrix ID of the user.
    mxid: String,

    /// The display name of the user, if any.
    display_name: Option<String>,

    /// The avatar URL of the user, if any.
    avatar_url: Option<String>,
}

impl MatrixUser {
    pub(crate) async fn load<C: HomeserverConnection + ?Sized>(
        conn: &C,
        user: &str,
    ) -> Result<MatrixUser, C::Error> {
        let mxid = conn.mxid(user);

        let info = conn.query_user(&mxid).await?;

        Ok(MatrixUser {
            mxid,
            display_name: info.displayname,
            avatar_url: info.avatar_url,
        })
    }
}
