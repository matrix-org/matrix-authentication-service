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

use std::{collections::HashSet, convert::TryFrom, str::FromStr};

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use itertools::Itertools;
use oauth2_types::{
    pkce,
    requests::{ResponseMode, ResponseType},
};
use serde::Serialize;
use sqlx::{Executor, FromRow, Postgres};
use url::Url;

use super::{
    super::{user::lookup_session, SessionInfo},
    authorization_code::{add_code, OAuth2Code},
};

#[derive(FromRow, Serialize)]
pub struct OAuth2Session {
    pub id: i64,
    user_session_id: Option<i64>,
    client_id: String,
    redirect_uri: String,
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

    pub async fn fetch_session(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> anyhow::Result<Option<SessionInfo>> {
        match self.user_session_id {
            Some(id) => {
                let info = lookup_session(executor, id).await?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    pub async fn fetch_code(
        &self,
        executor: impl Executor<'_, Database = Postgres>,
    ) -> anyhow::Result<String> {
        get_code_for_session(executor, self.id).await
    }

    pub async fn match_or_set_session(
        &mut self,
        executor: impl Executor<'_, Database = Postgres>,
        session: SessionInfo,
    ) -> anyhow::Result<SessionInfo> {
        match self.user_session_id {
            Some(id) if id == session.key() => Ok(session),
            Some(id) => Err(anyhow::anyhow!(
                "session mismatch, expected {}, got {}",
                id,
                session.key()
            )),
            None => {
                sqlx::query!(
                    "UPDATE oauth2_sessions SET user_session_id = $1 WHERE id = $2",
                    session.key(),
                    self.id,
                )
                .execute(executor)
                .await
                .context("could not update oauth2 session")?;
                Ok(session)
            }
        }
    }

    pub fn max_auth_time(&self) -> Option<DateTime<Utc>> {
        self.max_age
            .map(|d| Duration::seconds(i64::from(d)))
            .map(|d| self.created_at - d)
    }

    pub fn response_type(&self) -> anyhow::Result<HashSet<ResponseType>> {
        self.response_type
            .split(' ')
            .map(|s| {
                ResponseType::from_str(s).with_context(|| format!("invalid response type {}", s))
            })
            .collect()
    }

    pub fn response_mode(&self) -> anyhow::Result<ResponseMode> {
        self.response_mode.parse().context("invalid response mode")
    }

    pub fn redirect_uri(&self) -> anyhow::Result<Url> {
        self.redirect_uri.parse().context("invalid redirect uri")
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_session(
    executor: impl Executor<'_, Database = Postgres>,
    optional_session_id: Option<i64>,
    client_id: &str,
    redirect_uri: &Url,
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
                (user_session_id, client_id, redirect_uri, scope, state, nonce, max_age,
                 response_type, response_mode)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id, user_session_id, client_id, redirect_uri, scope, state, nonce, max_age,
                response_type, response_mode, created_at, updated_at
        "#,
        optional_session_id,
        client_id,
        redirect_uri.as_str(),
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

pub async fn get_session_by_id(
    executor: impl Executor<'_, Database = Postgres>,
    oauth2_session_id: i64,
) -> anyhow::Result<OAuth2Session> {
    sqlx::query_as!(
        OAuth2Session,
        r#"
            SELECT
                id, user_session_id, client_id, redirect_uri, scope, state, nonce,
                max_age, response_type, response_mode, created_at, updated_at
            FROM oauth2_sessions
            WHERE id = $1
        "#,
        oauth2_session_id
    )
    .fetch_one(executor)
    .await
    .context("could not fetch oauth2 session")
}

pub async fn get_code_for_session(
    executor: impl Executor<'_, Database = Postgres>,
    oauth2_session_id: i64,
) -> anyhow::Result<String> {
    sqlx::query_scalar!(
        r#"
            SELECT code
            FROM oauth2_codes
            WHERE oauth2_session_id = $1
        "#,
        oauth2_session_id
    )
    .fetch_one(executor)
    .await
    .context("could not fetch oauth2 code")
}
