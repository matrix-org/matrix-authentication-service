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

use async_graphql::{
    connection::{query, Connection, Edge, OpaqueCursor},
    Context, Object, ID,
};
use chrono::{DateTime, Utc};
use mas_storage::PostgresqlBackend;
use sqlx::PgPool;

use super::{BrowserSession, Cursor, NodeCursor, NodeType};

pub struct User(pub mas_data_model::User<PostgresqlBackend>);

impl From<mas_data_model::User<PostgresqlBackend>> for User {
    fn from(v: mas_data_model::User<PostgresqlBackend>) -> Self {
        Self(v)
    }
}

impl From<mas_data_model::BrowserSession<PostgresqlBackend>> for User {
    fn from(v: mas_data_model::BrowserSession<PostgresqlBackend>) -> Self {
        Self(v.user)
    }
}

#[Object]
impl User {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn username(&self) -> &str {
        &self.0.username
    }

    async fn primary_email(&self) -> Option<UserEmail> {
        self.0.primary_email.clone().map(UserEmail)
    }

    async fn browser_sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<Cursor, BrowserSession>, async_graphql::Error> {
        let database = ctx.data::<PgPool>()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let mut conn = database.acquire().await?;
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;

                let (has_previous_page, has_next_page, edges) =
                    mas_storage::user::get_paginated_user_sessions(
                        &mut conn, &self.0, before_id, after_id, first, last,
                    )
                    .await?;

                let mut connection = Connection::new(has_previous_page, has_next_page);
                connection.edges.extend(edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::BrowserSession, u.data)),
                        BrowserSession(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    async fn emails(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<Cursor, UserEmail, UserEmailsPagination>, async_graphql::Error> {
        let database = ctx.data::<PgPool>()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let mut conn = database.acquire().await?;
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;

                let (has_previous_page, has_next_page, edges) =
                    mas_storage::user::get_paginated_user_emails(
                        &mut conn, &self.0, before_id, after_id, first, last,
                    )
                    .await?;

                let mut connection = Connection::with_additional_fields(
                    has_previous_page,
                    has_next_page,
                    UserEmailsPagination(self.0.clone()),
                );
                connection.edges.extend(edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UserEmail, u.data)),
                        UserEmail(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

pub struct UserEmail(mas_data_model::UserEmail<PostgresqlBackend>);

#[Object]
impl UserEmail {
    async fn id(&self) -> ID {
        ID(self.0.data.to_string())
    }

    async fn email(&self) -> &str {
        &self.0.email
    }

    async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    async fn confirmed_at(&self) -> Option<DateTime<Utc>> {
        self.0.confirmed_at
    }
}

pub struct UserEmailsPagination(mas_data_model::User<PostgresqlBackend>);

#[Object]
impl UserEmailsPagination {
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64, async_graphql::Error> {
        let mut conn = ctx.data::<PgPool>()?.acquire().await?;
        let count = mas_storage::user::count_user_emails(&mut conn, &self.0).await?;
        Ok(count)
    }
}
