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

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    CompatSession, CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device, User,
};
use mas_storage::{
    compat::{CompatSessionFilter, CompatSessionRepository},
    Clock, Page, Pagination,
};
use rand::RngCore;
use sea_query::{enum_def, Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    iden::{CompatSessions, CompatSsoLogins},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
    DatabaseError, DatabaseInconsistencyError,
};

/// An implementation of [`CompatSessionRepository`] for a PostgreSQL connection
pub struct PgCompatSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatSessionRepository<'c> {
    /// Create a new [`PgCompatSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatSessionLookup {
    compat_session_id: Uuid,
    device_id: String,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    is_synapse_admin: bool,
}

impl TryFrom<CompatSessionLookup> for CompatSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CompatSessionLookup) -> Result<Self, Self::Error> {
        let id = value.compat_session_id.into();
        let device = Device::try_from(value.device_id).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sessions")
                .column("device_id")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => CompatSessionState::Valid,
            Some(finished_at) => CompatSessionState::Finished { finished_at },
        };

        let session = CompatSession {
            id,
            state,
            user_id: value.user_id.into(),
            device,
            created_at: value.created_at,
            is_synapse_admin: value.is_synapse_admin,
        };

        Ok(session)
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct CompatSessionAndSsoLoginLookup {
    compat_session_id: Uuid,
    device_id: String,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    is_synapse_admin: bool,
    compat_sso_login_id: Option<Uuid>,
    compat_sso_login_token: Option<String>,
    compat_sso_login_redirect_uri: Option<String>,
    compat_sso_login_created_at: Option<DateTime<Utc>>,
    compat_sso_login_fulfilled_at: Option<DateTime<Utc>>,
    compat_sso_login_exchanged_at: Option<DateTime<Utc>>,
}

impl TryFrom<CompatSessionAndSsoLoginLookup> for (CompatSession, Option<CompatSsoLogin>) {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CompatSessionAndSsoLoginLookup) -> Result<Self, Self::Error> {
        let id = value.compat_session_id.into();
        let device = Device::try_from(value.device_id).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sessions")
                .column("device_id")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => CompatSessionState::Valid,
            Some(finished_at) => CompatSessionState::Finished { finished_at },
        };

        let session = CompatSession {
            id,
            state,
            user_id: value.user_id.into(),
            device,
            created_at: value.created_at,
            is_synapse_admin: value.is_synapse_admin,
        };

        match (
            value.compat_sso_login_id,
            value.compat_sso_login_token,
            value.compat_sso_login_redirect_uri,
            value.compat_sso_login_created_at,
            value.compat_sso_login_fulfilled_at,
            value.compat_sso_login_exchanged_at,
        ) {
            (None, None, None, None, None, None) => Ok((session, None)),
            (
                Some(id),
                Some(login_token),
                Some(redirect_uri),
                Some(created_at),
                fulfilled_at,
                exchanged_at,
            ) => {
                let id = id.into();
                let redirect_uri = Url::parse(&redirect_uri).map_err(|e| {
                    DatabaseInconsistencyError::on("compat_sso_logins")
                        .column("redirect_uri")
                        .row(id)
                        .source(e)
                })?;

                let state = match (fulfilled_at, exchanged_at) {
                    (Some(fulfilled_at), None) => CompatSsoLoginState::Fulfilled {
                        fulfilled_at,
                        session_id: session.id,
                    },
                    (Some(fulfilled_at), Some(exchanged_at)) => CompatSsoLoginState::Exchanged {
                        fulfilled_at,
                        exchanged_at,
                        session_id: session.id,
                    },
                    _ => return Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
                };

                let login = CompatSsoLogin {
                    id,
                    redirect_uri,
                    login_token,
                    created_at,
                    state,
                };

                Ok((session, Some(login)))
            }
            _ => Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
        }
    }
}

#[async_trait]
impl<'c> CompatSessionRepository for PgCompatSessionRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_session.lookup",
        skip_all,
        fields(
            db.statement,
            compat_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSessionLookup,
            r#"
                SELECT compat_session_id
                     , device_id
                     , user_id
                     , created_at
                     , finished_at
                     , is_synapse_admin
                FROM compat_sessions
                WHERE compat_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_session.find_by_device",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %user.username,
            compat_session.device.id = device.as_str(),
        ),
    )]
    async fn find_by_device(
        &mut self,
        user: &User,
        device: &Device,
    ) -> Result<Option<CompatSession>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSessionLookup,
            r#"
                SELECT compat_session_id
                     , device_id
                     , user_id
                     , created_at
                     , finished_at
                     , is_synapse_admin
                FROM compat_sessions
                WHERE user_id = $1
                  AND device_id = $2
            "#,
            Uuid::from(user.id),
            device.as_str(),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_session.add",
        skip_all,
        fields(
            db.statement,
            compat_session.id,
            %user.id,
            %user.username,
            compat_session.device.id = device.as_str(),
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        is_synapse_admin: bool,
    ) -> Result<CompatSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_sessions (compat_session_id, user_id, device_id, created_at, is_synapse_admin)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            device.as_str(),
            created_at,
            is_synapse_admin,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatSession {
            id,
            state: CompatSessionState::default(),
            user_id: user.id,
            device,
            created_at,
            is_synapse_admin,
        })
    }

    #[tracing::instrument(
        name = "db.compat_session.finish",
        skip_all,
        fields(
            db.statement,
            %compat_session.id,
            user.id = %compat_session.user_id,
            compat_session.device.id = compat_session.device.as_str(),
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error> {
        let finished_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE compat_sessions cs
                SET finished_at = $2
                WHERE compat_session_id = $1
            "#,
            Uuid::from(compat_session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        let compat_session = compat_session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(compat_session)
    }

    #[tracing::instrument(
        name = "db.compat_session.list",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: CompatSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<(CompatSession, Option<CompatSsoLogin>)>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                CompatSessionAndSsoLoginLookupIden::CompatSessionId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)),
                CompatSessionAndSsoLoginLookupIden::DeviceId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserId)),
                CompatSessionAndSsoLoginLookupIden::UserId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CreatedAt)),
                CompatSessionAndSsoLoginLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)),
                CompatSessionAndSsoLoginLookupIden::FinishedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::IsSynapseAdmin)),
                CompatSessionAndSsoLoginLookupIden::IsSynapseAdmin,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginId,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::LoginToken)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginToken,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::RedirectUri)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginRedirectUri,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CreatedAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginCreatedAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::FulfilledAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginFulfilledAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::ExchangedAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginExchangedAt,
            )
            .from(CompatSessions::Table)
            .left_join(
                CompatSsoLogins::Table,
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId))
                    .equals((CompatSsoLogins::Table, CompatSsoLogins::CompatSessionId)),
            )
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
            .and_where_option(filter.auth_type().map(|auth_type| {
                if auth_type.is_sso_login() {
                    Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId))
                        .is_not_null()
                } else {
                    Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId)).is_null()
                }
            }))
            .generate_pagination(
                (CompatSessions::Table, CompatSessions::CompatSessionId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<CompatSessionAndSsoLoginLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.compat_session.count",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn count(&mut self, filter: CompatSessionFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = sea_query::Query::select()
            .expr(Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)).count())
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
            .and_where_option(filter.auth_type().map(|auth_type| {
                // Check if it is an SSO login by checking if there is a SSO login for the
                // session.
                let exists = Expr::exists(
                    Query::select()
                        .expr(Expr::cust("1"))
                        .from(CompatSsoLogins::Table)
                        .and_where(
                            Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSessionId))
                                .equals((CompatSessions::Table, CompatSessions::CompatSessionId)),
                        )
                        .take(),
                );

                if auth_type.is_sso_login() {
                    exists
                } else {
                    exists.not()
                }
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
        name = "db.compat_session.record_batch_activity",
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
                UPDATE compat_sessions
                SET last_active_at = GREATEST(t.last_active_at, compat_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, compat_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[]) 
                        AS t(compat_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE compat_sessions.compat_session_id = t.compat_session_id
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
}
