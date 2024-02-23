// Copyright 2023 The Matrix.org Foundation C.I.C.
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

//! A module containing PostgreSQL implementation of repositories for sessions

use async_trait::async_trait;
use mas_data_model::{CompatSession, CompatSessionState, Device, Session, SessionState, UserAgent};
use mas_storage::{
    app_session::{AppSession, AppSessionFilter, AppSessionRepository},
    Page, Pagination,
};
use oauth2_types::scope::{Scope, ScopeToken};
use sea_query::{
    Alias, ColumnRef, CommonTableExpression, Expr, PgFunc, PostgresQueryBuilder, Query, UnionType,
};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    errors::DatabaseInconsistencyError,
    iden::{CompatSessions, OAuth2Sessions},
    pagination::QueryBuilderExt,
    DatabaseError, ExecuteExt,
};

/// An implementation of [`AppSessionRepository`] for a PostgreSQL connection
pub struct PgAppSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgAppSessionRepository<'c> {
    /// Create a new [`PgAppSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

mod priv_ {
    // The enum_def macro generates a public enum, which we don't want, because it
    // triggers the missing docs warning

    use std::net::IpAddr;

    use chrono::{DateTime, Utc};
    use sea_query::enum_def;
    use uuid::Uuid;

    #[derive(sqlx::FromRow)]
    #[enum_def]
    pub(super) struct AppSessionLookup {
        pub(super) cursor: Uuid,
        pub(super) compat_session_id: Option<Uuid>,
        pub(super) oauth2_session_id: Option<Uuid>,
        pub(super) oauth2_client_id: Option<Uuid>,
        pub(super) user_session_id: Option<Uuid>,
        pub(super) user_id: Option<Uuid>,
        pub(super) scope_list: Option<Vec<String>>,
        pub(super) device_id: Option<String>,
        pub(super) created_at: DateTime<Utc>,
        pub(super) finished_at: Option<DateTime<Utc>>,
        pub(super) is_synapse_admin: Option<bool>,
        pub(super) user_agent: Option<String>,
        pub(super) last_active_at: Option<DateTime<Utc>>,
        pub(super) last_active_ip: Option<IpAddr>,
    }
}

use priv_::{AppSessionLookup, AppSessionLookupIden};

impl TryFrom<AppSessionLookup> for AppSession {
    type Error = DatabaseError;

    #[allow(clippy::too_many_lines)]
    fn try_from(value: AppSessionLookup) -> Result<Self, Self::Error> {
        // This is annoying to do, but we have to match on all the fields to determine
        // whether it's a compat session or an oauth2 session
        let AppSessionLookup {
            cursor,
            compat_session_id,
            oauth2_session_id,
            oauth2_client_id,
            user_session_id,
            user_id,
            scope_list,
            device_id,
            created_at,
            finished_at,
            is_synapse_admin,
            user_agent,
            last_active_at,
            last_active_ip,
        } = value;

        let user_agent = user_agent.map(UserAgent::parse);
        let user_session_id = user_session_id.map(Ulid::from);

        match (
            compat_session_id,
            oauth2_session_id,
            oauth2_client_id,
            user_id,
            scope_list,
            device_id,
            is_synapse_admin,
        ) {
            (
                Some(compat_session_id),
                None,
                None,
                Some(user_id),
                None,
                Some(device_id),
                Some(is_synapse_admin),
            ) => {
                let id = compat_session_id.into();
                let device = Device::try_from(device_id).map_err(|e| {
                    DatabaseInconsistencyError::on("compat_sessions")
                        .column("device_id")
                        .row(id)
                        .source(e)
                })?;

                let state = match finished_at {
                    None => CompatSessionState::Valid,
                    Some(finished_at) => CompatSessionState::Finished { finished_at },
                };

                let session = CompatSession {
                    id,
                    state,
                    user_id: user_id.into(),
                    device,
                    user_session_id,
                    created_at,
                    is_synapse_admin,
                    user_agent,
                    last_active_at,
                    last_active_ip,
                };

                Ok(AppSession::Compat(Box::new(session)))
            }

            (
                None,
                Some(oauth2_session_id),
                Some(oauth2_client_id),
                user_id,
                Some(scope_list),
                None,
                None,
            ) => {
                let id = oauth2_session_id.into();
                let scope: Result<Scope, _> =
                    scope_list.iter().map(|s| s.parse::<ScopeToken>()).collect();
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

                let session = Session {
                    id,
                    state,
                    created_at,
                    client_id: oauth2_client_id.into(),
                    user_id: user_id.map(Ulid::from),
                    user_session_id,
                    scope,
                    user_agent,
                    last_active_at,
                    last_active_ip,
                };

                Ok(AppSession::OAuth2(Box::new(session)))
            }

            _ => Err(DatabaseInconsistencyError::on("sessions")
                .row(cursor.into())
                .into()),
        }
    }
}

#[async_trait]
impl<'c> AppSessionRepository for PgAppSessionRepository<'c> {
    type Error = DatabaseError;

    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        name = "db.app_session.list",
        fields(
            db.statement,
        ),
        skip_all,
        err,
    )]
    async fn list(
        &mut self,
        filter: AppSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<AppSession>, Self::Error> {
        let mut oauth2_session_select = Query::select()
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)),
                AppSessionLookupIden::Cursor,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::CompatSessionId)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)),
                AppSessionLookupIden::Oauth2SessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId)),
                AppSessionLookupIden::Oauth2ClientId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId)),
                AppSessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)),
                AppSessionLookupIden::UserId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::ScopeList)),
                AppSessionLookupIden::ScopeList,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::DeviceId)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::CreatedAt)),
                AppSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)),
                AppSessionLookupIden::FinishedAt,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::IsSynapseAdmin)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserAgent)),
                AppSessionLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveAt)),
                AppSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveIp)),
                AppSessionLookupIden::LastActiveIp,
            )
            .from(OAuth2Sessions::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)).eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_null()
                } else {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.browser_session().map(|browser_session| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId))
                    .eq(Uuid::from(browser_session.id))
            }))
            .and_where_option(filter.device().map(|device| {
                Expr::val(device.to_scope_token().to_string()).eq(PgFunc::any(Expr::col((
                    OAuth2Sessions::Table,
                    OAuth2Sessions::ScopeList,
                ))))
            }))
            .clone();

        let compat_session_select = Query::select()
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                AppSessionLookupIden::Cursor,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                AppSessionLookupIden::CompatSessionId,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::Oauth2SessionId)
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::Oauth2ClientId)
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId)),
                AppSessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserId)),
                AppSessionLookupIden::UserId,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::ScopeList)
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)),
                AppSessionLookupIden::DeviceId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CreatedAt)),
                AppSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)),
                AppSessionLookupIden::FinishedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::IsSynapseAdmin)),
                AppSessionLookupIden::IsSynapseAdmin,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserAgent)),
                AppSessionLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveAt)),
                AppSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveIp)),
                AppSessionLookupIden::LastActiveIp,
            )
            .from(CompatSessions::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((CompatSessions::Table, CompatSessions::UserId)).eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_null()
                } else {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.browser_session().map(|browser_session| {
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId))
                    .eq(Uuid::from(browser_session.id))
            }))
            .and_where_option(filter.device().map(|device| {
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)).eq(device.to_string())
            }))
            .clone();

        let common_table_expression = CommonTableExpression::new()
            .query(
                oauth2_session_select
                    .union(UnionType::All, compat_session_select)
                    .clone(),
            )
            .table_name(Alias::new("sessions"))
            .clone();

        let with_clause = Query::with().cte(common_table_expression).clone();

        let select = Query::select()
            .column(ColumnRef::Asterisk)
            .from(Alias::new("sessions"))
            .generate_pagination(AppSessionLookupIden::Cursor, pagination)
            .clone();

        let (sql, arguments) = with_clause.query(select).build_sqlx(PostgresQueryBuilder);

        let edges: Vec<AppSessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.app_session.count",
        fields(
            db.statement,
        ),
        skip_all,
        err,
    )]
    async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error> {
        let mut oauth2_session_select = Query::select()
            .expr(Expr::cust("1"))
            .from(OAuth2Sessions::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)).eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_null()
                } else {
                    Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.browser_session().map(|browser_session| {
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId))
                    .eq(Uuid::from(browser_session.id))
            }))
            .and_where_option(filter.device().map(|device| {
                Expr::val(device.to_scope_token().to_string()).eq(PgFunc::any(Expr::col((
                    OAuth2Sessions::Table,
                    OAuth2Sessions::ScopeList,
                ))))
            }))
            .clone();

        let compat_session_select = Query::select()
            .expr(Expr::cust("1"))
            .from(CompatSessions::Table)
            .and_where_option(filter.user().map(|user| {
                Expr::col((CompatSessions::Table, CompatSessions::UserId)).eq(Uuid::from(user.id))
            }))
            .and_where_option(filter.state().map(|state| {
                if state.is_active() {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_null()
                } else {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_not_null()
                }
            }))
            .and_where_option(filter.browser_session().map(|browser_session| {
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId))
                    .eq(Uuid::from(browser_session.id))
            }))
            .and_where_option(filter.device().map(|device| {
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)).eq(device.to_string())
            }))
            .clone();

        let common_table_expression = CommonTableExpression::new()
            .query(
                oauth2_session_select
                    .union(UnionType::All, compat_session_select)
                    .clone(),
            )
            .table_name(Alias::new("sessions"))
            .clone();

        let with_clause = Query::with().cte(common_table_expression).clone();

        let select = Query::select()
            .expr(Expr::cust("COUNT(*)"))
            .from(Alias::new("sessions"))
            .clone();

        let (sql, arguments) = with_clause.query(select).build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::Device;
    use mas_storage::{
        app_session::{AppSession, AppSessionFilter},
        clock::MockClock,
        oauth2::OAuth2SessionRepository,
        Pagination, RepositoryAccess,
    };
    use oauth2_types::{
        requests::GrantType,
        scope::{Scope, OPENID},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_app_repo(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        let all = AppSessionFilter::new().for_user(&user);
        let active = all.active_only();
        let finished = all.finished_only();
        let pagination = Pagination::first(10);

        assert_eq!(repo.app_session().count(all).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert!(full_list.edges.is_empty());
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let compat_session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device.clone(), None, false)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(
            active_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Finish the session
        let compat_session = repo
            .compat_session()
            .finish(&clock, compat_session)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 1);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        // Start an OAuth2 session
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Vec::new(), // TODO: contacts are not yet saved
                // vec!["contact@example.com".to_owned()],
                Some("First client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let device2 = Device::generate(&mut rng);
        let scope = Scope::from_iter([OPENID, device2.to_scope_token()]);

        // We're moving the clock forward by 1 minute between each session to ensure
        // we're getting consistent ordering in lists.
        clock.advance(Duration::minutes(1));

        let oauth_session = repo
            .oauth2_session()
            .add(&mut rng, &clock, &client, Some(&user), None, scope)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 2);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 1);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 2);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(
            active_list.edges[0],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        // Finish the session
        let oauth_session = repo
            .oauth2_session()
            .finish(&clock, oauth_session)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 2);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 2);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 2);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 2);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        // Query by device
        let filter = AppSessionFilter::new().for_device(&device);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 1);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(
            list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        let filter = AppSessionFilter::new().for_device(&device2);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 1);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(
            list.edges[0],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        // Create a second user
        let user2 = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();

        // If we list/count for this user, we should get nothing
        let filter = AppSessionFilter::new().for_user(&user2);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 0);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert!(list.edges.is_empty());
    }
}
