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
    Context, Description, Object, ID,
};
use chrono::{DateTime, Utc};
use mas_storage::{
    compat::CompatSsoLoginRepository,
    oauth2::OAuth2SessionRepository,
    upstream_oauth2::UpstreamOAuthLinkRepository,
    user::{BrowserSessionRepository, UserEmailRepository},
    PgRepository, Repository,
};
use sqlx::PgPool;

use super::{
    compat_sessions::CompatSsoLogin, BrowserSession, Cursor, NodeCursor, NodeType, OAuth2Session,
    UpstreamOAuth2Link,
};

#[derive(Description)]
/// A user is an individual's account.
pub struct User(pub mas_data_model::User);

impl From<mas_data_model::User> for User {
    fn from(v: mas_data_model::User) -> Self {
        Self(v)
    }
}

impl From<mas_data_model::BrowserSession> for User {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v.user)
    }
}

#[Object(use_type_description)]
impl User {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::User.id(self.0.id)
    }

    /// Username chosen by the user.
    async fn username(&self) -> &str {
        &self.0.username
    }

    /// Primary email address of the user.
    async fn primary_email(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<UserEmail>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        Ok(repo.user_email().get_primary(&self.0).await?.map(UserEmail))
    }

    /// Get the list of compatibility SSO logins, chronologically sorted
    async fn compat_sso_logins(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, CompatSsoLogin>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;

                let page = repo
                    .compat_sso_login()
                    .list_paginated(&self.0, before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::CompatSsoLogin, u.id)),
                        CompatSsoLogin(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of active browser sessions, chronologically sorted
    async fn browser_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, BrowserSession>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;

                let page = repo
                    .browser_session()
                    .list_active_paginated(&self.0, before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::BrowserSession, u.id)),
                        BrowserSession(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of emails, chronologically sorted
    async fn emails(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UserEmail, UserEmailsPagination>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;

                let page = repo
                    .user_email()
                    .list_paginated(&self.0, before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    UserEmailsPagination(self.0.clone()),
                );
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UserEmail, u.id)),
                        UserEmail(u),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of OAuth 2.0 sessions, chronologically sorted
    async fn oauth2_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, OAuth2Session>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;

                let page = repo
                    .oauth2_session()
                    .list_paginated(&self.0, before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|s| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::OAuth2Session, s.id)),
                        OAuth2Session(s),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of upstream OAuth 2.0 links
    async fn upstream_oauth2_links(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UpstreamOAuth2Link>, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;

                let page = repo
                    .upstream_oauth_link()
                    .list_paginated(&self.0, before_id, after_id, first, last)
                    .await?;

                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(page.edges.into_iter().map(|s| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UpstreamOAuth2Link, s.id)),
                        UpstreamOAuth2Link::new(s),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

/// A user email address
#[derive(Description)]
pub struct UserEmail(pub mas_data_model::UserEmail);

#[Object(use_type_description)]
impl UserEmail {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UserEmail.id(self.0.id)
    }

    /// Email address
    async fn email(&self) -> &str {
        &self.0.email
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the email address was confirmed. Is `null` if the email was never
    /// verified by the user.
    async fn confirmed_at(&self) -> Option<DateTime<Utc>> {
        self.0.confirmed_at
    }
}

pub struct UserEmailsPagination(mas_data_model::User);

#[Object]
impl UserEmailsPagination {
    /// Identifies the total count of items in the connection.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize, async_graphql::Error> {
        let mut repo = PgRepository::from_pool(ctx.data::<PgPool>()?).await?;
        let count = repo.user_email().count(&self.0).await?;
        Ok(count)
    }
}
