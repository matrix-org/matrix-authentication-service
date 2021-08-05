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

use std::{collections::HashSet, convert::TryFrom};

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use itertools::Itertools;
use oauth2_types::{
    pkce,
    requests::{ResponseMode, ResponseType},
};
use serde::Serialize;
use sqlx::{Executor, FromRow, Postgres};

use super::{user::lookup_session, SessionInfo};

#[derive(FromRow, Serialize)]
pub struct OAuth2Session {
    id: i64,
    user_session_id: Option<i64>,
    client_id: String,
    scope: String,
    pub state: Option<String>,
    nonce: Option<String>,
    max_age: Option<i32>,
    response_type: String,
    response_mode: String,

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

    pub async fn fetch_session<'e>(
        &self,
        executor: impl Executor<'e, Database = Postgres>,
    ) -> anyhow::Result<Option<SessionInfo>> {
        match self.user_session_id {
            Some(id) => {
                let info = lookup_session(executor, id).await?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    pub fn max_auth_time(&self) -> Option<DateTime<Utc>> {
        self.max_age
            .map(|d| Duration::seconds(i64::from(d)))
            .map(|d| self.created_at - d)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_session(
    executor: impl Executor<'_, Database = Postgres>,
    optional_session_id: Option<i64>,
    client_id: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
    max_age: Option<Duration>,
    response_type: &HashSet<ResponseType>,
    response_mode: ResponseMode,
) -> anyhow::Result<OAuth2Session> {
    // Checked convertion of duration to i32, maxing at i32::MAX
    let max_age = max_age.map(|d| i32::try_from(d.num_seconds()).unwrap_or(i32::MAX));
    let response_mode = response_mode.to_string();
    let response_type: String = {
        let it = response_type.iter().map(ToString::to_string);
        Itertools::intersperse(it, " ".to_string()).collect()
    };

    sqlx::query_as!(
        OAuth2Session,
        r#"
            INSERT INTO oauth2_sessions 
                (user_session_id, client_id, scope, state, nonce, max_age, response_type, response_mode)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING
                id, user_session_id, client_id, scope, state, nonce, max_age, 
                response_type, response_mode, created_at, updated_at
        "#,
        optional_session_id,
        client_id,
        scope,
        state,
        nonce,
        max_age,
        response_type,
        response_mode,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 session")
}

#[derive(FromRow, Serialize)]
pub struct OAuth2Code {
    id: i64,
    oauth2_session_id: i64,
    pub code: String,
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
