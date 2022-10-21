// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::str::FromStr;

use chrono::Utc;
use mas_data_model::{Client, User};
use oauth2_types::scope::{Scope, ScopeToken};
use sqlx::PgExecutor;
use ulid::Ulid;
use uuid::Uuid;

use crate::PostgresqlBackend;

pub async fn fetch_client_consent(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    client: &Client<PostgresqlBackend>,
) -> anyhow::Result<Scope> {
    let scope_tokens: Vec<String> = sqlx::query_scalar!(
        r#"
            SELECT scope_token
            FROM oauth2_consents
            WHERE user_id = $1 AND oauth2_client_id = $2
        "#,
        Uuid::from(user.data),
        Uuid::from(client.data),
    )
    .fetch_all(executor)
    .await?;

    let scope: Result<Scope, _> = scope_tokens
        .into_iter()
        .map(|s| ScopeToken::from_str(&s))
        .collect();

    Ok(scope?)
}

pub async fn insert_client_consent(
    executor: impl PgExecutor<'_>,
    user: &User<PostgresqlBackend>,
    client: &Client<PostgresqlBackend>,
    scope: &Scope,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let (tokens, ids): (Vec<String>, Vec<Uuid>) = scope
        .iter()
        .map(|token| {
            (
                token.to_string(),
                Uuid::from(Ulid::from_datetime(now.into())),
            )
        })
        .unzip();

    sqlx::query!(
        r#"
            INSERT INTO oauth2_consents
                (oauth2_consent_id, user_id, oauth2_client_id, scope_token, created_at)
            SELECT id, $2, $3, scope_token, $5 FROM UNNEST($1::uuid[], $4::text[]) u(id, scope_token)
            ON CONFLICT (user_id, oauth2_client_id, scope_token) DO UPDATE SET refreshed_at = $5
        "#,
        &ids,
        Uuid::from(user.data),
        Uuid::from(client.data),
        &tokens,
        now,
    )
    .execute(executor)
    .await?;

    Ok(())
}
