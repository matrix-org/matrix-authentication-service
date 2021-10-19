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
use mas_data_model::{
    Authentication, AuthorizationCode, BrowserSession, Client, Pkce, Session, User,
};
use oauth2_types::pkce;
use sqlx::PgExecutor;
use thiserror::Error;
use warp::reject::Reject;

use crate::storage::{DatabaseInconsistencyError, PostgresqlBackend};

pub async fn add_code(
    executor: impl PgExecutor<'_>,
    oauth2_session_id: i64,
    code: &str,
    pkce: &Option<pkce::AuthorizationRequest>,
) -> anyhow::Result<AuthorizationCode<PostgresqlBackend>> {
    let code_challenge_method = pkce.as_ref().map(|c| c.code_challenge_method as i16);
    let code_challenge = pkce.as_ref().map(|c| &c.code_challenge);
    let id = sqlx::query_scalar!(
        r#"
            INSERT INTO oauth2_codes
                (oauth2_session_id, code, code_challenge_method, code_challenge)
            VALUES
                ($1, $2, $3, $4)
            RETURNING
                id
        "#,
        oauth2_session_id,
        code,
        code_challenge_method,
        code_challenge,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 authorization code")?;

    let pkce = pkce
        .as_ref()
        .map(|c| Pkce::new(c.code_challenge_method, c.code_challenge.clone()));

    Ok(AuthorizationCode {
        data: id,
        code: code.to_string(),
        pkce,
    })
}

struct OAuth2CodeLookup {
    id: i64,
    oauth2_session_id: i64,
    client_id: String,
    redirect_uri: String,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<i16>,
    user_session_id: Option<i64>,
    user_session_created_at: Option<DateTime<Utc>>,
    user_id: Option<i64>,
    user_username: Option<String>,
    user_session_last_authentication_id: Option<i64>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
}

fn browser_session_from_database(
    user_session_id: Option<i64>,
    user_session_created_at: Option<DateTime<Utc>>,
    user_id: Option<i64>,
    user_username: Option<String>,
    user_session_last_authentication_id: Option<i64>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
) -> Result<Option<BrowserSession<PostgresqlBackend>>, DatabaseInconsistencyError> {
    match (
        user_session_id,
        user_session_created_at,
        user_id,
        user_username,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(session_id), Some(session_created_at), Some(user_id), Some(user_username)) => {
            let user = User {
                data: user_id,
                username: user_username,
                sub: format!("fake-sub-{}", user_id),
            };

            let last_authentication = match (
                user_session_last_authentication_id,
                user_session_last_authentication_created_at,
            ) {
                (None, None) => None,
                (Some(id), Some(created_at)) => Some(Authentication {
                    data: id,
                    created_at,
                }),
                _ => return Err(DatabaseInconsistencyError),
            };

            Ok(Some(BrowserSession {
                data: session_id,
                created_at: session_created_at,
                user,
                last_authentication,
            }))
        }
        _ => Err(DatabaseInconsistencyError),
    }
}

#[derive(Debug, Error)]
#[error("failed to lookup oauth2 code")]
pub enum CodeLookupError {
    Database(#[from] sqlx::Error),
    Inconsistency(#[from] DatabaseInconsistencyError),
}

impl Reject for CodeLookupError {}

impl CodeLookupError {
    #[must_use]
    pub fn not_found(&self) -> bool {
        matches!(self, &CodeLookupError::Database(sqlx::Error::RowNotFound))
    }
}

#[allow(clippy::too_many_lines)]
pub async fn lookup_code(
    executor: impl PgExecutor<'_>,
    code: &str,
) -> Result<
    (
        AuthorizationCode<PostgresqlBackend>,
        Session<PostgresqlBackend>,
    ),
    CodeLookupError,
> {
    let res = sqlx::query_as!(
        OAuth2CodeLookup,
        r#"
            SELECT
                oc.id,
                oc.code_challenge,
                oc.code_challenge_method,
                os.id          AS "oauth2_session_id!",
                os.client_id   AS "client_id!",
                os.redirect_uri,
                os.scope       AS "scope!",
                os.nonce,
                us.id          AS "user_session_id?",
                us.created_at  AS "user_session_created_at?",
                u.id           AS "user_id?",
                u.username     AS "user_username?",
                usa.id         AS "user_session_last_authentication_id?",
                usa.created_at AS "user_session_last_authentication_created_at?"
            FROM oauth2_codes oc
            INNER JOIN oauth2_sessions os
              ON os.id = oc.oauth2_session_id
            LEFT JOIN user_sessions us
              ON us.id = os.user_session_id
            LEFT JOIN user_session_authentications usa
              ON usa.session_id = us.id
            LEFT JOIN users u
              ON u.id = us.user_id
            WHERE oc.code = $1
            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        code,
    )
    .fetch_one(executor)
    .await?;

    let pkce = match (res.code_challenge_method, res.code_challenge) {
        (None, None) => None,
        (Some(0 /* Plain */), Some(challenge)) => {
            Some(Pkce::new(pkce::CodeChallengeMethod::Plain, challenge))
        }
        (Some(1 /* S256 */), Some(challenge)) => {
            Some(Pkce::new(pkce::CodeChallengeMethod::S256, challenge))
        }
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let code = AuthorizationCode {
        data: res.id,
        code: code.to_string(),
        pkce,
    };

    let client = Client {
        data: (),
        client_id: res.client_id,
    };

    let browser_session = browser_session_from_database(
        res.user_session_id,
        res.user_session_created_at,
        res.user_id,
        res.user_username,
        res.user_session_last_authentication_id,
        res.user_session_last_authentication_created_at,
    )?;

    let scope = res.scope.parse().map_err(|_e| DatabaseInconsistencyError)?;

    let redirect_uri = res
        .redirect_uri
        .parse()
        .map_err(|_e| DatabaseInconsistencyError)?;

    let session = Session {
        data: res.oauth2_session_id,
        client,
        browser_session,
        scope,
        redirect_uri,
        nonce: res.nonce,
    };

    Ok((code, session))
}

pub async fn consume_code(
    executor: impl PgExecutor<'_>,
    code: AuthorizationCode<PostgresqlBackend>,
) -> anyhow::Result<()> {
    // TODO: mark the code as invalid instead to allow invalidating the whole
    // session on code reuse
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_codes
            WHERE id = $1
        "#,
        code.data,
    )
    .execute(executor)
    .await
    .context("could not consume authorization code")?;

    if res.rows_affected() == 1 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no row were affected when consuming authorization code"
        ))
    }
}
