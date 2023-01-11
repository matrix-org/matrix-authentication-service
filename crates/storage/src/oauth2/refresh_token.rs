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

use chrono::{DateTime, Utc};
use mas_data_model::{AccessToken, RefreshToken, RefreshTokenState, Session};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, DatabaseError};

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        user_session.id = %session.user_session_id,
        client.id = %session.client_id,
        refresh_token.id,
    ),
    err,
)]
pub async fn add_refresh_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &Session,
    access_token: &AccessToken,
    refresh_token: String,
) -> Result<RefreshToken, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("refresh_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_refresh_tokens
                (oauth2_refresh_token_id, oauth2_session_id, oauth2_access_token_id,
                 refresh_token, created_at)
            VALUES
                ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        Uuid::from(access_token.id),
        refresh_token,
        created_at,
    )
    .execute(executor)
    .await?;

    Ok(RefreshToken {
        id,
        state: RefreshTokenState::default(),
        session_id: session.id,
        refresh_token,
        access_token_id: Some(access_token.id),
        created_at,
    })
}

struct OAuth2RefreshTokenLookup {
    oauth2_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    oauth2_access_token_id: Option<Uuid>,
    oauth2_session_id: Uuid,
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::too_many_lines)]
pub async fn lookup_refresh_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<RefreshToken>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2RefreshTokenLookup,
        r#"
            SELECT oauth2_refresh_token_id
                 , refresh_token
                 , created_at
                 , consumed_at
                 , oauth2_access_token_id
                 , oauth2_session_id
            FROM oauth2_refresh_tokens

            WHERE refresh_token = $1
        "#,
        token,
    )
    .fetch_one(&mut *conn)
    .await?;

    let state = match res.consumed_at {
        None => RefreshTokenState::Valid,
        Some(consumed_at) => RefreshTokenState::Consumed { consumed_at },
    };

    let refresh_token = RefreshToken {
        id: res.oauth2_refresh_token_id.into(),
        state,
        session_id: res.oauth2_session_id.into(),
        refresh_token: res.refresh_token,
        created_at: res.created_at,
        access_token_id: res.oauth2_access_token_id.map(Ulid::from),
    };

    Ok(Some(refresh_token))
}

#[tracing::instrument(
    skip_all,
    fields(
        %refresh_token.id,
    ),
    err,
)]
pub async fn consume_refresh_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    refresh_token: RefreshToken,
) -> Result<RefreshToken, DatabaseError> {
    let consumed_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_refresh_tokens
            SET consumed_at = $2
            WHERE oauth2_refresh_token_id = $1
        "#,
        Uuid::from(refresh_token.id),
        consumed_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)?;

    refresh_token
        .consume(consumed_at)
        .map_err(DatabaseError::to_invalid_operation)
}
