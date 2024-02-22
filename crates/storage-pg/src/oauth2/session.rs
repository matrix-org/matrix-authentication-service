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

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, Client, Session, SessionState, User};
use mas_storage::{
    oauth2::{OAuth2SessionFilter, OAuth2SessionRepository},
    Clock, Page, Pagination,
};
use oauth2_types::scope::{Scope, ScopeToken};
use rand::RngCore;
use sea_query::{enum_def, extension::postgres::PgExpr, Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    iden::{OAuth2Sessions, UserSessions},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
    DatabaseError, DatabaseInconsistencyError,
};

/// An implementation of [`OAuth2SessionRepository`] for a PostgreSQL connection
pub struct PgOAuth2SessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2SessionRepository<'c> {
    /// Create a new [`PgOAuth2SessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct OAuthSessionLookup {
    oauth2_session_id: Uuid,
    user_id: Option<Uuid>,
    user_session_id: Option<Uuid>,
    oauth2_client_id: Uuid,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpAddr>,
}

impl TryFrom<OAuthSessionLookup> for Session {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuthSessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.oauth2_session_id);
        let scope: Result<Scope, _> = value
            .scope_list
            .iter()
            .map(|s| s.parse::<ScopeToken>())
            .collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => SessionState::Valid,
            Some(finished_at) => SessionState::Finished { finished_at },
        };

        Ok(Session {
            id,
            state,
            created_at: value.created_at,
            client_id: value.oauth2_client_id.into(),
            user_id: value.user_id.map(Ulid::from),
            user_session_id: value.user_session_id.map(Ulid::from),
            scope,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        })
    }
}

#[async_trait]
impl<'c> OAuth2SessionRepository for PgOAuth2SessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_session.lookup",
        skip_all,
        fields(
            db.statement,
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error> {
        let res = sqlx::query_as!(
            OAuthSessionLookup,
            r#"
                SELECT oauth2_session_id
                     , user_id
                     , user_session_id
                     , oauth2_client_id
                     , scope_list
                     , created_at
                     , finished_at
                     , user_agent
                     , last_active_at
                     , last_active_ip as "last_active_ip: IpAddr"
                FROM oauth2_sessions

                WHERE oauth2_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_session.add",
        skip_all,
        fields(
            db.statement,
            %client.id,
            session.id,
            session.scope = %scope,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: Option<&User>,
        user_session: Option<&BrowserSession>,
        scope: Scope,
    ) -> Result<Session, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_sessions
                    ( oauth2_session_id
                    , user_id
                    , user_session_id
                    , oauth2_client_id
                    , scope_list
                    , created_at
                    )
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            user.map(|u| Uuid::from(u.id)),
            user_session.map(|s| Uuid::from(s.id)),
            Uuid::from(client.id),
            &scope_list,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Session {
            id,
            state: SessionState::Valid,
            created_at,
            user_id: user.map(|u| u.id),
            user_session_id: user_session.map(|s| s.id),
            client_id: client.id,
            scope,
            user_agent: None,
            last_active_at: None,
            last_active_ip: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_session.finish",
        skip_all,
        fields(
            db.statement,
            %session.id,
            %session.scope,
            client.id = %session.client_id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        session: Session,
    ) -> Result<Session, Self::Error> {
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
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.list",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)),
                OAuthSessionLookupIden::Oauth2SessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)),
                OAuthSessionLookupIden::UserId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId)),
                OAuthSessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId)),
                OAuthSessionLookupIden::Oauth2ClientId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::ScopeList)),
                OAuthSessionLookupIden::ScopeList,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::CreatedAt)),
                OAuthSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)),
                OAuthSessionLookupIden::FinishedAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserAgent)),
                OAuthSessionLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveAt)),
                OAuthSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveIp)),
                OAuthSessionLookupIden::LastActiveIp,
            )
            .from(OAuth2Sessions::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)).eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.client().map(|client| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId))
                    .eq(Uuid::from(client.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_null()
                } else {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.scope().map(|scope| {
                let scope: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::ScopeList)).contains(scope)
            }))
            .generate_pagination(
                (OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<OAuthSessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(Session::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.count",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)).count())
            .from(OAuth2Sessions::Table)
            .and_where_option(filter.user().map(|user| {
                // Check for user ownership by querying the user_sessions table
                // The query plan is the same as if we were joining the tables instead
                Expr::exists(
                    Query::select()
                        .expr(Expr::cust("1"))
                        .from(UserSessions::Table)
                        .and_where(
                            Expr::col((UserSessions::Table, UserSessions::UserId))
                                .eq(Uuid::from(user.id)),
                        )
                        .and_where(
                            Expr::col((UserSessions::Table, UserSessions::UserSessionId))
                                .equals((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId)),
                        )
                        .take(),
                )
            }))
            .and_where_option(filter.client().map(|client| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId))
                    .eq(Uuid::from(client.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_null()
                } else {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.scope().map(|scope| {
                let scope: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::ScopeList)).contains(scope)
            }))
            .build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.record_batch_activity",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn record_batch_activity(
        &mut self,
        activity: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error> {
        let mut ids = Vec::with_capacity(activity.len());
        let mut last_activities = Vec::with_capacity(activity.len());
        let mut ips = Vec::with_capacity(activity.len());

        for (id, last_activity, ip) in activity {
            ids.push(Uuid::from(id));
            last_activities.push(last_activity);
            ips.push(ip);
        }

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_sessions
                SET last_active_at = GREATEST(t.last_active_at, oauth2_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, oauth2_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[]) 
                        AS t(oauth2_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE oauth2_sessions.oauth2_session_id = t.oauth2_session_id
            "#,
            &ids,
            &last_activities,
            &ips as &[Option<IpAddr>],
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, ids.len().try_into().unwrap_or(u64::MAX))?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.oauth2_session.record_user_agent",
        skip_all,
        fields(
            db.statement,
            %session.id,
            %session.scope,
            client.id = %session.client_id,
            session.user_agent = %user_agent,
        ),
        err,
    )]
    async fn record_user_agent(
        &mut self,
        mut session: Session,
        user_agent: String,
    ) -> Result<Session, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_sessions
                SET user_agent = $2
                WHERE oauth2_session_id = $1
            "#,
            Uuid::from(session.id),
            user_agent,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        session.user_agent = Some(user_agent);

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(session)
    }
}
