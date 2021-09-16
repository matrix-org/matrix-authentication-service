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

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};

#[derive(Debug)]
pub struct OAuth2RefreshToken {
    pub id: i64,
    oauth2_session_id: i64,
    oauth2_access_token_id: Option<i64>,
    pub token: String,
    next_token_id: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

pub async fn add_refresh_token(
    executor: impl Executor<'_, Database = Postgres>,
    oauth2_session_id: i64,
    oauth2_access_token_id: i64,
    token: &str,
) -> anyhow::Result<OAuth2RefreshToken> {
    sqlx::query_as!(
        OAuth2RefreshToken,
        r#"
            INSERT INTO oauth2_refresh_tokens
                (oauth2_session_id, oauth2_access_token_id, token)
            VALUES
                ($1, $2, $3)
            RETURNING
                id, oauth2_session_id, oauth2_access_token_id, token, next_token_id, 
                created_at, updated_at
        "#,
        oauth2_session_id,
        oauth2_access_token_id,
        token,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 refresh token")
}

pub struct OAuth2RefreshTokenLookup {
    pub id: i64,
    pub oauth2_session_id: i64,
    pub oauth2_access_token_id: Option<i64>,
    pub client_id: String,
    pub scope: String,
}

pub async fn lookup_refresh_token(
    executor: impl Executor<'_, Database = Postgres>,
    token: &str,
) -> anyhow::Result<OAuth2RefreshTokenLookup> {
    sqlx::query_as!(
        OAuth2RefreshTokenLookup,
        r#"
            SELECT
                rt.id,
                rt.oauth2_session_id,
                rt.oauth2_access_token_id,
                os.client_id AS "client_id!",
                os.scope     AS "scope!"
            FROM oauth2_refresh_tokens rt
            INNER JOIN oauth2_sessions os
              ON os.id = rt.oauth2_session_id
            WHERE rt.token = $1 AND rt.next_token_id IS NULL
        "#,
        token,
    )
    .fetch_one(executor)
    .await
    .context("failed to fetch oauth2 refresh token")
}

pub async fn replace_refresh_token(
    executor: impl Executor<'_, Database = Postgres>,
    refresh_token_id: i64,
    next_refresh_token_id: i64,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_refresh_tokens
            SET next_token_id = $2
            WHERE id = $1
        "#,
        refresh_token_id,
        next_refresh_token_id
    )
    .execute(executor)
    .await
    .context("failed to update oauth2 refresh token")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no row were affected when updating refresh token"
        ))
    }
}
