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

use std::convert::TryFrom;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{Executor, FromRow, Postgres};
use thiserror::Error;

#[derive(FromRow, Serialize)]
pub struct OAuth2AccessToken {
    pub id: i64,
    pub oauth2_session_id: i64,
    pub token: String,
    expires_after: i32,
    created_at: DateTime<Utc>,
}

pub async fn add_access_token(
    executor: impl Executor<'_, Database = Postgres>,
    oauth2_session_id: i64,
    token: &str,
    expires_after: Duration,
) -> anyhow::Result<OAuth2AccessToken> {
    // Checked convertion of duration to i32, maxing at i32::MAX
    let expires_after = i32::try_from(expires_after.num_seconds()).unwrap_or(i32::MAX);

    sqlx::query_as!(
        OAuth2AccessToken,
        r#"
            INSERT INTO oauth2_access_tokens
                (oauth2_session_id, token, expires_after)
            VALUES
                ($1, $2, $3)
            RETURNING
                id, oauth2_session_id, token, expires_after, created_at
        "#,
        oauth2_session_id,
        token,
        expires_after,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 access token")
}

#[derive(Debug)]
pub struct OAuth2AccessTokenLookup {
    pub active: bool,
    pub username: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    expires_after: i32,
}

impl OAuth2AccessTokenLookup {
    #[must_use]
    pub fn exp(&self) -> DateTime<Utc> {
        self.created_at + Duration::seconds(i64::from(self.expires_after))
    }
}

#[derive(Debug, Error)]
#[error("failed to lookup access token")]
pub struct AccessTokenLookupError(#[from] sqlx::Error);

impl AccessTokenLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self.0, sqlx::Error::RowNotFound)
    }
}

pub async fn lookup_access_token(
    executor: impl Executor<'_, Database = Postgres>,
    token: &str,
) -> Result<OAuth2AccessTokenLookup, AccessTokenLookupError> {
    let res = sqlx::query_as!(
        OAuth2AccessTokenLookup,
        r#"
            SELECT
                 u.username      AS "username!",
                us.active        AS "active!",
                os.client_id     AS "client_id!",
                os.scope         AS "scope!",
                at.created_at    AS "created_at!",
                at.expires_after AS "expires_after!"
            FROM oauth2_access_tokens at
            INNER JOIN oauth2_sessions os
              ON os.id = at.oauth2_session_id
            INNER JOIN user_sessions us
              ON us.id = os.user_session_id
            INNER JOIN users u
              ON u.id = us.user_id
            WHERE at.token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .await?;

    Ok(res)
}

pub async fn revoke_access_token(
    executor: impl Executor<'_, Database = Postgres>,
    id: i64,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_access_tokens
            WHERE id = $1
        "#,
        id,
    )
    .execute(executor)
    .await
    .context("could not revoke access tokens")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("no row were affected when revoking token"))
    }
}

pub async fn cleanup_expired(
    executor: impl Executor<'_, Database = Postgres>,
) -> anyhow::Result<u64> {
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_access_tokens
            WHERE created_at + (expires_after * INTERVAL '1 second') + INTERVAL '15 minutes' < now()
        "#,
    )
    .execute(executor)
    .await
    .context("could not cleanup expired access tokens")?;

    Ok(res.rows_affected())
}
