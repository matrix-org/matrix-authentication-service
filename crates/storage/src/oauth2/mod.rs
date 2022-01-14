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

use mas_data_model::Session;
use sqlx::PgExecutor;

use crate::PostgresqlBackend;

pub mod access_token;
pub mod authorization_grant;
pub mod refresh_token;

pub async fn end_oauth_session(
    executor: impl PgExecutor<'_>,
    session: Session<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_sessions
            SET ended_at = NOW()
            WHERE id = $1
        "#,
        session.data,
    )
    .execute(executor)
    .await?;

    anyhow::ensure!(res.rows_affected() == 1);

    Ok(())
}
