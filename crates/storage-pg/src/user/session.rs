// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Authentication, BrowserSession, Password, UpstreamOAuthLink, User};
use mas_storage::{user::BrowserSessionRepository, Clock, Page, Pagination};
use rand::RngCore;
use sea_query::{Expr, IntoColumnRef, PostgresQueryBuilder};
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    pagination::QueryBuilderExt, sea_query_sqlx::map_values, tracing::ExecuteExt, DatabaseError,
    DatabaseInconsistencyError, LookupResultExt,
};

/// An implementation of [`BrowserSessionRepository`] for a PostgreSQL
/// connection
pub struct PgBrowserSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgBrowserSessionRepository<'c> {
    /// Create a new [`PgBrowserSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[sea_query::enum_def]
struct SessionLookup {
    user_session_id: Uuid,
    user_session_created_at: DateTime<Utc>,
    user_session_finished_at: Option<DateTime<Utc>>,
    user_id: Uuid,
    user_username: String,
    user_primary_user_email_id: Option<Uuid>,
    last_authentication_id: Option<Uuid>,
    last_authd_at: Option<DateTime<Utc>>,
}

#[derive(sea_query::Iden)]
enum UserSessions {
    Table,
    UserSessionId,
    CreatedAt,
    FinishedAt,
    UserId,
}

#[derive(sea_query::Iden)]
enum Users {
    Table,
    UserId,
    Username,
    PrimaryUserEmailId,
}

#[derive(sea_query::Iden)]
enum SessionAuthentication {
    Table,
    UserSessionAuthenticationId,
    UserSessionId,
    CreatedAt,
}

impl TryFrom<SessionLookup> for BrowserSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.user_id);
        let user = User {
            id,
            username: value.user_username,
            sub: id.to_string(),
            primary_user_email_id: value.user_primary_user_email_id.map(Into::into),
        };

        let last_authentication = match (value.last_authentication_id, value.last_authd_at) {
            (Some(id), Some(created_at)) => Some(Authentication {
                id: id.into(),
                created_at,
            }),
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on(
                    "user_session_authentications",
                ))
            }
        };

        Ok(BrowserSession {
            id: value.user_session_id.into(),
            user,
            created_at: value.user_session_created_at,
            finished_at: value.user_session_finished_at,
            last_authentication,
        })
    }
}

#[async_trait]
impl<'c> BrowserSessionRepository for PgBrowserSessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.browser_session.lookup",
        skip_all,
        fields(
            db.statement,
            user_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error> {
        let res = sqlx::query_as!(
            SessionLookup,
            r#"
                SELECT s.user_session_id
                     , s.created_at                     AS "user_session_created_at"
                     , s.finished_at                     AS "user_session_finished_at"
                     , u.user_id
                     , u.username                       AS "user_username"
                     , u.primary_user_email_id          AS "user_primary_user_email_id"
                     , a.user_session_authentication_id AS "last_authentication_id?"
                     , a.created_at                     AS "last_authd_at?"
                FROM user_sessions s
                INNER JOIN users u
                    USING (user_id)
                LEFT JOIN user_session_authentications a
                    USING (user_session_id)
                WHERE s.user_session_id = $1
                ORDER BY a.created_at DESC
                LIMIT 1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await
        .to_option()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.browser_session.add",
        skip_all,
        fields(
            db.statement,
            %user.id,
            user_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
    ) -> Result<BrowserSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_sessions (user_session_id, user_id, created_at)
                VALUES ($1, $2, $3)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let session = BrowserSession {
            id,
            // XXX
            user: user.clone(),
            created_at,
            finished_at: None,
            last_authentication: None,
        };

        Ok(session)
    }

    #[tracing::instrument(
        name = "db.browser_session.finish",
        skip_all,
        fields(
            db.statement,
            %user_session.id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        mut user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error> {
        let finished_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_sessions
                SET finished_at = $1
                WHERE user_session_id = $2
            "#,
            finished_at,
            Uuid::from(user_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_session.finished_at = Some(finished_at);

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(user_session)
    }

    #[tracing::instrument(
        name = "db.browser_session.list",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: mas_storage::user::BrowserSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error> {
        let (sql, values) = sea_query::Query::select()
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::UserSessionId)),
                SessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::CreatedAt)),
                SessionLookupIden::UserSessionCreatedAt,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::FinishedAt)),
                SessionLookupIden::UserSessionFinishedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::UserId)),
                SessionLookupIden::UserId,
            )
            .expr_as(
                Expr::col((Users::Table, Users::Username)),
                SessionLookupIden::UserUsername,
            )
            .expr_as(
                Expr::col((Users::Table, Users::PrimaryUserEmailId)),
                SessionLookupIden::UserPrimaryUserEmailId,
            )
            .expr_as(
                Expr::value(None::<Uuid>),
                SessionLookupIden::LastAuthenticationId,
            )
            .expr_as(
                Expr::value(None::<DateTime<Utc>>),
                SessionLookupIden::LastAuthdAt,
            )
            .from(UserSessions::Table)
            .inner_join(
                Users::Table,
                Expr::col((UserSessions::Table, UserSessions::UserId))
                    .equals((Users::Table, Users::UserId)),
            )
            .and_where_option(
                filter
                    .user()
                    .map(|user| Expr::col((Users::Table, Users::UserId)).eq(Uuid::from(user.id))),
            )
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((UserSessions::Table, UserSessions::FinishedAt)).is_null()
                } else {
                    Expr::col((UserSessions::Table, UserSessions::FinishedAt)).is_not_null()
                }
            }))
            .generate_pagination(
                (UserSessions::Table, UserSessions::UserSessionId).into_column_ref(),
                pagination,
            )
            .build(PostgresQueryBuilder);

        let arguments = map_values(values);

        let edges: Vec<SessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(BrowserSession::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.browser_session.authenticate_with_password",
        skip_all,
        fields(
            db.statement,
            %user_session.id,
            %user_password.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        mut user_session: BrowserSession,
        user_password: &Password,
    ) -> Result<BrowserSession, Self::Error> {
        let _user_password = user_password;
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
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
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_session.last_authentication = Some(Authentication { id, created_at });

        Ok(user_session)
    }

    #[tracing::instrument(
        name = "db.browser_session.authenticate_with_upstream",
        skip_all,
        fields(
            db.statement,
            %user_session.id,
            %upstream_oauth_link.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        mut user_session: BrowserSession,
        upstream_oauth_link: &UpstreamOAuthLink,
    ) -> Result<BrowserSession, Self::Error> {
        let _upstream_oauth_link = upstream_oauth_link;
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
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
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_session.last_authentication = Some(Authentication { id, created_at });

        Ok(user_session)
    }
}
