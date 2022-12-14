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

use mas_data_model::{Authentication, BrowserSession, Password, UpstreamOAuthLink};
use rand::Rng;
use sqlx::PgExecutor;
use ulid::Ulid;
use uuid::Uuid;

use crate::Clock;

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user_session.user.id,
        %user_password.id,
        %user_session.id,
        user_session_authentication.id,
    ),
    err,
)]
pub async fn authenticate_session_with_password(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user_session: &mut BrowserSession,
    user_password: &Password,
) -> Result<(), sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record(
        "user_session_authentication.id",
        tracing::field::display(id),
    );

    sqlx::query!(
        r#"
            INSERT INTO user_session_authentications
                (user_session_authentication_id, user_session_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user_session.id),
        created_at,
    )
    .execute(executor)
    .await?;

    user_session.last_authentication = Some(Authentication { id, created_at });

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        user.id = %user_session.user.id,
        %upstream_oauth_link.id,
        %user_session.id,
        user_session_authentication.id,
    ),
    err,
)]
pub async fn authenticate_session_with_upstream(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user_session: &mut BrowserSession,
    upstream_oauth_link: &UpstreamOAuthLink,
) -> Result<(), sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record(
        "user_session_authentication.id",
        tracing::field::display(id),
    );

    sqlx::query!(
        r#"
            INSERT INTO user_session_authentications
                (user_session_authentication_id, user_session_id, created_at)
            VALUES ($1, $2, $3)
        "#,
        Uuid::from(id),
        Uuid::from(user_session.id),
        created_at,
    )
    .execute(executor)
    .await?;

    user_session.last_authentication = Some(Authentication { id, created_at });

    Ok(())
}
