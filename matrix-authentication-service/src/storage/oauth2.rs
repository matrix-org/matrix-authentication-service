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

use super::{user::lookup_session, SessionInfo};

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

#[derive(FromRow, Serialize)]
pub struct OAuth2AccessToken {
    id: i64,
    oauth2_session_id: i64,
    token: String,
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

pub struct OAuth2AccessTokenLookup {
    pub active: bool,
    pub username: String,
    pub client_id: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    expires_after: i32,
}

impl OAuth2AccessTokenLookup {
    pub fn exp(&self) -> DateTime<Utc> {
        self.created_at + Duration::seconds(i64::from(self.expires_after))
    }
}

pub async fn lookup_access_token(
    executor: impl Executor<'_, Database = Postgres>,
    token: &str,
) -> anyhow::Result<OAuth2AccessTokenLookup> {
    sqlx::query_as!(
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
    .await
    .context("could not introspect oauth2 access token")
}

pub struct OAuth2CodeLookup {
    pub id: i64,
    pub oauth2_session_id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

pub async fn lookup_code(
    executor: impl Executor<'_, Database = Postgres>,
    code: &str,
) -> anyhow::Result<OAuth2CodeLookup> {
    sqlx::query_as!(
        OAuth2CodeLookup,
        r#"
            SELECT
                oc.id,
                os.id        AS "oauth2_session_id!",
                os.client_id AS "client_id!",
                os.redirect_uri,
                os.scope     AS "scope!"
            FROM oauth2_codes oc
            INNER JOIN oauth2_sessions os
              ON os.id = oc.oauth2_session_id
            WHERE oc.code = $1
        "#,
        code,
    )
    .fetch_one(executor)
    .await
    .context("could not lookup oauth2 code")
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
