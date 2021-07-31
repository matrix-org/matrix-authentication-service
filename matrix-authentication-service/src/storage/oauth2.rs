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
use oauth2_types::pkce;
use serde::Serialize;
use sqlx::{Executor, FromRow, Postgres};

#[derive(FromRow, Serialize)]
pub struct OAuth2Session {
    id: i64,
    user_session_id: Option<i64>,
    client_id: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,

    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OAuth2Session {
    pub async fn add_code<'e>(
        &self,
        executor: impl Executor<'e, Database = Postgres>,
        code: &str,
        code_challenge: &Option<pkce::Request>,
    ) -> anyhow::Result<OAuth2Code> {
        add_code(executor, self.id, code, code_challenge).await
    }
}

pub async fn start_session(
    executor: impl Executor<'_, Database = Postgres>,
    optional_session_id: Option<i64>,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
) -> anyhow::Result<OAuth2Session> {
    sqlx::query_as!(
        OAuth2Session,
        r#"
            INSERT INTO oauth2_sessions 
                (user_session_id, client_id, scope, state, nonce)
            VALUES
                ($1, $2, $3, $4, $5)
            RETURNING
                id, user_session_id, client_id, scope, state, nonce, created_at, updated_at
        "#,
        optional_session_id,
        client_id,
        scope,
        state,
        nonce,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 session")
}

#[derive(FromRow, Serialize)]
pub struct OAuth2Code {
    id: i64,
    oauth2_session_id: i64,
    code: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<i16>,
}

pub async fn add_code(
    executor: impl Executor<'_, Database = Postgres>,
    oauth2_session_id: i64,
    code: &str,
    code_challenge: &Option<pkce::Request>,
) -> anyhow::Result<OAuth2Code> {
    let code_challenge_method = code_challenge
        .as_ref()
        .map(|c| c.code_challenge_method as i16);
    let code_challenge = code_challenge.as_ref().map(|c| &c.code_challenge);
    sqlx::query_as!(
        OAuth2Code,
        r#"
            INSERT INTO oauth2_codes
                (oauth2_session_id, code, code_challenge_method, code_challenge)
            VALUES
                ($1, $2, $3, $4)
            RETURNING
                id, oauth2_session_id, code, code_challenge_method, code_challenge
        "#,
        oauth2_session_id,
        code,
        code_challenge_method,
        code_challenge,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 authorization code")
}
