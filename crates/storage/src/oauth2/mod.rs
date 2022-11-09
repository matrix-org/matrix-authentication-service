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

use std::collections::{BTreeSet, HashMap};

use anyhow::Context;
use mas_data_model::{BrowserSession, Session, User};
use sqlx::{postgres::PgArguments, Arguments, PgConnection, PgExecutor};
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use self::client::lookup_clients;
use crate::{
    pagination::{generate_pagination, process_page},
    user::lookup_active_session,
    Clock, PostgresqlBackend,
};

pub mod access_token;
pub mod authorization_grant;
pub mod client;
pub mod consent;
pub mod refresh_token;

#[tracing::instrument(
    skip_all,
    fields(
        session.id = %session.data,
        user.id = %session.browser_session.user.data,
        user_session.id = %session.browser_session.data,
        client.id = %session.client.data,
    ),
    err(Debug),
)]
pub async fn end_oauth_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    session: Session<PostgresqlBackend>,
) -> Result<(), anyhow::Error> {
    let finished_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE oauth2_sessions
            SET finished_at = $2
            WHERE oauth2_session_id = $1
        "#,
        Uuid::from(session.data),
        finished_at,
    )
    .execute(executor)
    .await?;

    anyhow::ensure!(res.rows_affected() == 1);

    Ok(())
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
        user.id = %user.data,
        user.username = user.username,
    ),
    err(Display),
)]
pub async fn get_paginated_user_oauth_sessions(
    conn: &mut PgConnection,
    user: &User<PostgresqlBackend>,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<Session<PostgresqlBackend>>), anyhow::Error> {
    let mut query = String::from(
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

    let mut arguments = PgArguments::default();

    query += " WHERE us.user_id = ";
    arguments.add(Uuid::from(user.data));
    arguments.format_placeholder(&mut query)?;

    generate_pagination(
        &mut query,
        "oauth2_session_id",
        &mut arguments,
        before,
        after,
        first,
        last,
    )?;

    let page: Vec<OAuthSessionLookup> = sqlx::query_as_with(&query, arguments)
        .fetch_all(&mut *conn)
        .instrument(info_span!(
            "Fetch paginated user oauth sessions",
            query = query
        ))
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let client_ids: BTreeSet<Ulid> = page
        .iter()
        .map(|i| Ulid::from(i.oauth2_client_id))
        .collect();

    let browser_session_ids: BTreeSet<Ulid> =
        page.iter().map(|i| Ulid::from(i.user_session_id)).collect();

    let clients = lookup_clients(&mut *conn, client_ids).await?;

    // TODO: this can generate N queries instead of batching. This is less than
    // ideal
    let mut browser_sessions: HashMap<Ulid, BrowserSession<PostgresqlBackend>> = HashMap::new();
    for id in browser_session_ids {
        let v = lookup_active_session(&mut *conn, id).await?;
        browser_sessions.insert(id, v);
    }

    let page: Result<Vec<_>, _> = page
        .into_iter()
        .map(|item| {
            let client = clients
                .get(&Ulid::from(item.oauth2_client_id))
                .context("client was not fetched")?
                .clone();

            let browser_session = browser_sessions
                .get(&Ulid::from(item.user_session_id))
                .context("browser session was not fetched")?
                .clone();

            let scope = item.scope.parse()?;

            anyhow::Ok(Session {
                data: Ulid::from(item.oauth2_session_id),
                client,
                browser_session,
                scope,
            })
        })
        .collect();

    Ok((has_previous_page, has_next_page, page?))
}
