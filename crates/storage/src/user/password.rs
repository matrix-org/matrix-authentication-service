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

use chrono::{DateTime, Utc};
use mas_data_model::{Password, User};
use rand::Rng;
use sqlx::PgExecutor;
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt};

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
        user_password.id,
        user_password.version = version,
    ),
    err,
)]
pub async fn add_user_password(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: &User,
    version: u16,
    hashed_password: String,
    upgraded_from: Option<Password>,
) -> Result<Password, DatabaseError> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("user_password.id", tracing::field::display(id));

    let upgraded_from_id = upgraded_from.map(|p| p.id);

    sqlx::query!(
        r#"
            INSERT INTO user_passwords
                (user_password_id, user_id, hashed_password, version, upgraded_from_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        Uuid::from(id),
        Uuid::from(user.id),
        hashed_password,
        i32::from(version),
        upgraded_from_id.map(Uuid::from),
        created_at,
    )
    .execute(executor)
    .await?;

    Ok(Password {
        id,
        hashed_password,
        version,
        upgraded_from_id,
        created_at,
    })
}

struct UserPasswordLookup {
    user_password_id: Uuid,
    hashed_password: String,
    version: i32,
    upgraded_from_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
    ),
    err,
)]
pub async fn lookup_user_password(
    executor: impl PgExecutor<'_>,
    user: &User,
) -> Result<Option<Password>, DatabaseError> {
    let res = sqlx::query_as!(
        UserPasswordLookup,
        r#"
            SELECT up.user_password_id
                 , up.hashed_password
                 , up.version
                 , up.upgraded_from_id
                 , up.created_at
            FROM user_passwords up
            WHERE up.user_id = $1
            ORDER BY up.created_at DESC
            LIMIT 1
        "#,
        Uuid::from(user.id),
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let id = Ulid::from(res.user_password_id);

    let version = res.version.try_into().map_err(|e| {
        DatabaseInconsistencyError::on("user_passwords")
            .column("version")
            .row(id)
            .source(e)
    })?;

    let upgraded_from_id = res.upgraded_from_id.map(Ulid::from);
    let created_at = res.created_at;
    let hashed_password = res.hashed_password;

    Ok(Some(Password {
        id,
        hashed_password,
        version,
        upgraded_from_id,
        created_at,
    }))
}
