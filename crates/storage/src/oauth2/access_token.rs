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

use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, AccessTokenState, Session};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, DatabaseError, LookupResultExt};

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        user_session.id = %session.user_session_id,
        client.id = %session.client_id,
        access_token.id,
    ),
    err,
)]
pub async fn add_access_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &Session,
    access_token: String,
    expires_after: Duration,
) -> Result<AccessToken, sqlx::Error> {
    let created_at = clock.now();
    let expires_at = created_at + expires_after;
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);

    tracing::Span::current().record("access_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_access_tokens
                (oauth2_access_token_id, oauth2_session_id, access_token, created_at, expires_at)
            VALUES
                ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        &access_token,
        created_at,
        expires_at,
    )
    .execute(executor)
    .await?;

    Ok(AccessToken {
        id,
        state: AccessTokenState::default(),
        access_token,
        session_id: session.id,
        created_at,
        expires_at,
    })
}

#[derive(Debug)]
pub struct OAuth2AccessTokenLookup {
    oauth2_access_token_id: Uuid,
    oauth2_session_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<OAuth2AccessTokenLookup> for AccessToken {
    fn from(value: OAuth2AccessTokenLookup) -> Self {
        let state = match value.revoked_at {
            None => AccessTokenState::Valid,
            Some(revoked_at) => AccessTokenState::Revoked { revoked_at },
        };

        Self {
            id: value.oauth2_access_token_id.into(),
            state,
            session_id: value.oauth2_session_id.into(),
            access_token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn find_access_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<AccessToken>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2AccessTokenLookup,
        r#"
            SELECT oauth2_access_token_id
                 , access_token
                 , created_at
                 , expires_at
                 , revoked_at
                 , oauth2_session_id

            FROM oauth2_access_tokens

            WHERE access_token = $1
        "#,
        token,
    )
    .fetch_one(&mut *conn)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

#[tracing::instrument(
    skip_all,
    fields(access_token.id = %access_token_id),
    err,
)]
pub async fn lookup_access_token(
    conn: &mut PgConnection,
    access_token_id: Ulid,
) -> Result<Option<AccessToken>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2AccessTokenLookup,
        r#"
            SELECT oauth2_access_token_id
                 , access_token
                 , created_at
                 , expires_at
                 , revoked_at
                 , oauth2_session_id

            FROM oauth2_access_tokens

            WHERE oauth2_access_token_id = $1
        "#,
        Uuid::from(access_token_id),
    )
    .fetch_one(&mut *conn)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

#[tracing::instrument(
    skip_all,
    fields(
        %access_token.id,
        session.id = %access_token.session_id,
    ),
    err,
)]
pub async fn revoke_access_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    access_token: AccessToken,
) -> Result<AccessToken, DatabaseError> {
    let revoked_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_access_tokens
            SET revoked_at = $2
            WHERE oauth2_access_token_id = $1
        "#,
        Uuid::from(access_token.id),
        revoked_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)?;

    access_token
        .revoke(revoked_at)
        .map_err(DatabaseError::to_invalid_operation)
}

pub async fn cleanup_expired(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
) -> Result<u64, sqlx::Error> {
    // Cleanup token which expired more than 15 minutes ago
    let threshold = clock.now() - Duration::minutes(15);
    let res = sqlx::query!(
        r#"
            DELETE FROM oauth2_access_tokens
            WHERE expires_at < $1
        "#,
        threshold,
    )
    .execute(executor)
    .await?;

    Ok(res.rows_affected())
}
