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

use mas_data_model::{Client, User};
use oauth2_types::scope::{Scope, ScopeToken};
use sqlx::PgExecutor;

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
        user.data,
        client.data,
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
    let tokens: Vec<String> = scope.iter().map(ToString::to_string).collect();

    sqlx::query!(
        r#"
            INSERT INTO oauth2_consents (user_id, oauth2_client_id, scope_token)
            SELECT $1, $2, scope_token FROM UNNEST($3::text[]) scope_token
            ON CONFLICT (user_id, oauth2_client_id, scope_token) DO UPDATE SET updated_at = NOW()
        "#,
        user.data,
        client.data,
        &tokens,
    )
    .execute(executor)
    .await?;

    Ok(())
}
