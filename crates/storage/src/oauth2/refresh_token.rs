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
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{
    AccessToken, Authentication, BrowserSession, Client, RefreshToken, Session, User, UserEmail,
};
use sqlx::PgExecutor;

use crate::{DatabaseInconsistencyError, IdAndCreationTime, PostgresqlBackend};

pub async fn add_refresh_token(
    executor: impl PgExecutor<'_>,
    session: &Session<PostgresqlBackend>,
    access_token: AccessToken<PostgresqlBackend>,
    token: &str,
) -> anyhow::Result<RefreshToken<PostgresqlBackend>> {
    let res = sqlx::query_as!(
        IdAndCreationTime,
        r#"
            INSERT INTO oauth2_refresh_tokens
                (oauth2_session_id, oauth2_access_token_id, token)
            VALUES
                ($1, $2, $3)
            RETURNING
                id, created_at
        "#,
        session.data,
        access_token.data,
        token,
    )
    .fetch_one(executor)
    .await
    .context("could not insert oauth2 refresh token")?;

    Ok(RefreshToken {
        data: res.id,
        token: token.to_string(),
        access_token: Some(access_token),
        created_at: res.created_at,
    })
}

struct OAuth2RefreshTokenLookup {
    refresh_token_id: i64,
    refresh_token: String,
    refresh_token_created_at: DateTime<Utc>,
    access_token_id: Option<i64>,
    access_token: Option<String>,
    access_token_expires_after: Option<i32>,
    access_token_created_at: Option<DateTime<Utc>>,
    session_id: i64,
    client_id: String,
    scope: String,
    user_session_id: i64,
    user_session_created_at: DateTime<Utc>,
    user_id: i64,
    user_username: String,
    user_session_last_authentication_id: Option<i64>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
    user_email_id: Option<i64>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_lines)]
pub async fn lookup_active_refresh_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> anyhow::Result<(RefreshToken<PostgresqlBackend>, Session<PostgresqlBackend>)> {
    let res = sqlx::query_as!(
        OAuth2RefreshTokenLookup,
        r#"
            SELECT
                rt.id              AS refresh_token_id,
                rt.token           AS refresh_token,
                rt.created_at      AS refresh_token_created_at,
                at.id              AS "access_token_id?",
                at.token           AS "access_token?",
                at.expires_after   AS "access_token_expires_after?",
                at.created_at      AS "access_token_created_at?",
                os.id              AS "session_id!",
                os.client_id       AS "client_id!",
                os.scope           AS "scope!",
                us.id              AS "user_session_id!",
                us.created_at      AS "user_session_created_at!",
                 u.id              AS "user_id!",
                 u.username        AS "user_username!",
                usa.id             AS "user_session_last_authentication_id?",
                usa.created_at     AS "user_session_last_authentication_created_at?",
                ue.id              AS "user_email_id?",
                ue.email           AS "user_email?",
                ue.created_at      AS "user_email_created_at?",
                ue.confirmed_at    AS "user_email_confirmed_at?"
            FROM oauth2_refresh_tokens rt
            LEFT JOIN oauth2_access_tokens at
              ON at.id = rt.oauth2_access_token_id
            INNER JOIN oauth2_sessions os
              ON os.id = rt.oauth2_session_id
            INNER JOIN user_sessions us
              ON us.id = os.user_session_id
            INNER JOIN users u
              ON u.id = us.user_id
            LEFT JOIN user_session_authentications usa
              ON usa.session_id = us.id
            LEFT JOIN user_emails ue
              ON ue.id = u.primary_email_id

            WHERE rt.token = $1
              AND rt.next_token_id IS NULL
              AND us.active
              AND os.ended_at IS NULL

            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        token,
    )
    .fetch_one(executor)
    .await
    .context("failed to fetch oauth2 refresh token")?;

    let access_token = match (
        res.access_token_id,
        res.access_token,
        res.access_token_created_at,
        res.access_token_expires_after,
    ) {
        (None, None, None, None) => None,
        (Some(id), Some(token), Some(created_at), Some(expires_after)) => Some(AccessToken {
            data: id,
            jti: format!("{}", id),
            token,
            created_at,
            expires_after: Duration::seconds(expires_after.into()),
        }),
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let refresh_token = RefreshToken {
        data: res.refresh_token_id,
        token: res.refresh_token,
        created_at: res.refresh_token_created_at,
        access_token,
    };

    let client = Client {
        data: (),
        client_id: res.client_id,
    };

    let primary_email = match (
        res.user_email_id,
        res.user_email,
        res.user_email_created_at,
        res.user_email_confirmed_at,
    ) {
        (Some(id), Some(email), Some(created_at), confirmed_at) => Some(UserEmail {
            data: id,
            email,
            created_at,
            confirmed_at,
        }),
        (None, None, None, None) => None,
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let user = User {
        data: res.user_id,
        username: res.user_username,
        sub: format!("fake-sub-{}", res.user_id),
        primary_email,
    };

    let last_authentication = match (
        res.user_session_last_authentication_id,
        res.user_session_last_authentication_created_at,
    ) {
        (None, None) => None,
        (Some(id), Some(created_at)) => Some(Authentication {
            data: id,
            created_at,
        }),
        _ => return Err(DatabaseInconsistencyError.into()),
    };

    let browser_session = BrowserSession {
        data: res.user_session_id,
        created_at: res.user_session_created_at,
        user,
        last_authentication,
    };

    let session = Session {
        data: res.session_id,
        client,
        browser_session,
        scope: res.scope.parse().context("invalid scope in database")?,
    };

    Ok((refresh_token, session))
}

pub async fn replace_refresh_token(
    executor: impl PgExecutor<'_>,
    refresh_token: &RefreshToken<PostgresqlBackend>,
    next_refresh_token: &RefreshToken<PostgresqlBackend>,
) -> anyhow::Result<()> {
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_refresh_tokens
            SET next_token_id = $2
            WHERE id = $1
        "#,
        refresh_token.data,
        next_refresh_token.data
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
