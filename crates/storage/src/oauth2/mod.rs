// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use mas_data_model::{Session, User};
use sqlx::{PgConnection, PgExecutor, QueryBuilder};
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    Clock, DatabaseError, DatabaseInconsistencyError,
};

pub mod access_token;
pub mod authorization_grant;
pub mod client;
pub mod consent;
pub mod refresh_token;
pub mod session;

#[tracing::instrument(
    skip_all,
    fields(
        %session.id,
        user_session.id = %session.user_session_id,
        client.id = %session.client_id,
    ),
    err,
)]
pub async fn end_oauth_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    session: Session,
) -> Result<(), DatabaseError> {
    let finished_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_sessions
            SET finished_at = $2
            WHERE oauth2_session_id = $1
        "#,
        Uuid::from(session.id),
        finished_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}

#[derive(sqlx::FromRow)]
struct OAuthSessionLookup {
    oauth2_session_id: Uuid,
    user_session_id: Uuid,
    oauth2_client_id: Uuid,
    scope: String,
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
    ),
    err,
)]
pub async fn get_paginated_user_oauth_sessions(
    conn: &mut PgConnection,
    user: &User,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<Session>), DatabaseError> {
    let mut query = QueryBuilder::new(
        r#"
            SELECT
                os.oauth2_session_id,
                os.user_session_id,
                os.oauth2_client_id,
                os.scope,
                os.created_at,
                os.finished_at
            FROM oauth2_sessions os
            LEFT JOIN user_sessions us
              USING (user_session_id)
        "#,
    );

    query
        .push(" WHERE us.user_id = ")
        .push_bind(Uuid::from(user.id))
        .generate_pagination("oauth2_session_id", before, after, first, last)?;

    let span = info_span!(
        "Fetch paginated user oauth sessions",
        db.statement = query.sql()
    );
    let page: Vec<OAuthSessionLookup> = query
        .build_query_as()
        .fetch_all(&mut *conn)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let page: Result<Vec<_>, DatabaseInconsistencyError> = page
        .into_iter()
        .map(|item| {
            let id = Ulid::from(item.oauth2_session_id);
            let scope = item.scope.parse().map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_sessions")
                    .column("scope")
                    .row(id)
                    .source(e)
            })?;

            Ok(Session {
                id: Ulid::from(item.oauth2_session_id),
                client_id: item.oauth2_client_id.into(),
                user_session_id: item.user_session_id.into(),
                scope,
            })
        })
        .collect();

    Ok((has_previous_page, has_next_page, page?))
}
