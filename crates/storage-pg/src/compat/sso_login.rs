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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{CompatSession, CompatSsoLogin, CompatSsoLoginState, User};
use mas_storage::{compat::CompatSsoLoginRepository, Clock, Page, Pagination};
use rand::RngCore;
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    pagination::QueryBuilderExt, tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError,
};

/// An implementation of [`CompatSsoLoginRepository`] for a PostgreSQL
/// connection
pub struct PgCompatSsoLoginRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatSsoLoginRepository<'c> {
    /// Create a new [`PgCompatSsoLoginRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
struct CompatSsoLoginLookup {
    compat_sso_login_id: Uuid,
    login_token: String,
    redirect_uri: String,
    created_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    compat_session_id: Option<Uuid>,
}

impl TryFrom<CompatSsoLoginLookup> for CompatSsoLogin {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: CompatSsoLoginLookup) -> Result<Self, Self::Error> {
        let id = res.compat_sso_login_id.into();
        let redirect_uri = Url::parse(&res.redirect_uri).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sso_logins")
                .column("redirect_uri")
                .row(id)
                .source(e)
        })?;

        let state = match (res.fulfilled_at, res.exchanged_at, res.compat_session_id) {
            (None, None, None) => CompatSsoLoginState::Pending,
            (Some(fulfilled_at), None, Some(session_id)) => CompatSsoLoginState::Fulfilled {
                fulfilled_at,
                session_id: session_id.into(),
            },
            (Some(fulfilled_at), Some(exchanged_at), Some(session_id)) => {
                CompatSsoLoginState::Exchanged {
                    fulfilled_at,
                    exchanged_at,
                    session_id: session_id.into(),
                }
            }
            _ => return Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
        };

        Ok(CompatSsoLogin {
            id,
            login_token: res.login_token,
            redirect_uri,
            created_at: res.created_at,
            state,
        })
    }
}

#[async_trait]
impl<'c> CompatSsoLoginRepository for PgCompatSsoLoginRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_sso_login.lookup",
        skip_all,
        fields(
            db.statement,
            compat_sso_login.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSsoLogin>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSsoLoginLookup,
            r#"
                SELECT compat_sso_login_id
                     , login_token
                     , redirect_uri
                     , created_at
                     , fulfilled_at
                     , exchanged_at
                     , compat_session_id

                FROM compat_sso_logins
                WHERE compat_sso_login_id = $1
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
        name = "db.compat_sso_login.find_by_token",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        login_token: &str,
    ) -> Result<Option<CompatSsoLogin>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSsoLoginLookup,
            r#"
                SELECT compat_sso_login_id
                     , login_token
                     , redirect_uri
                     , created_at
                     , fulfilled_at
                     , exchanged_at
                     , compat_session_id

                FROM compat_sso_logins
                WHERE login_token = $1
            "#,
            login_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.add",
        skip_all,
        fields(
            db.statement,
            compat_sso_login.id,
            compat_sso_login.redirect_uri = %redirect_uri,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        login_token: String,
        redirect_uri: Url,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_sso_login.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_sso_logins
                    (compat_sso_login_id, login_token, redirect_uri, created_at)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            &login_token,
            redirect_uri.as_str(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatSsoLogin {
            id,
            login_token,
            redirect_uri,
            created_at,
            state: CompatSsoLoginState::default(),
        })
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.fulfill",
        skip_all,
        fields(
            db.statement,
            %compat_sso_login.id,
            %compat_session.id,
            compat_session.device.id = compat_session.device.as_str(),
            user.id = %compat_session.user_id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        compat_session: &CompatSession,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let fulfilled_at = clock.now();
        let compat_sso_login = compat_sso_login
            .fulfill(fulfilled_at, compat_session)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE compat_sso_logins
                SET
                    compat_session_id = $2,
                    fulfilled_at = $3
                WHERE
                    compat_sso_login_id = $1
            "#,
            Uuid::from(compat_sso_login.id),
            Uuid::from(compat_session.id),
            fulfilled_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_sso_login)
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.exchange",
        skip_all,
        fields(
            db.statement,
            %compat_sso_login.id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let exchanged_at = clock.now();
        let compat_sso_login = compat_sso_login
            .exchange(exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE compat_sso_logins
                SET
                    exchanged_at = $2
                WHERE
                    compat_sso_login_id = $1
            "#,
            Uuid::from(compat_sso_login.id),
            exchanged_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_sso_login)
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.list_paginated",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %user.username,
        ),
        err
    )]
    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<CompatSsoLogin>, Self::Error> {
        let mut query = QueryBuilder::new(
            r#"
                SELECT cl.compat_sso_login_id
                     , cl.login_token
                     , cl.redirect_uri
                     , cl.created_at
                     , cl.fulfilled_at
                     , cl.exchanged_at
                     , cl.compat_session_id

                FROM compat_sso_logins cl
                INNER JOIN compat_sessions cs USING (compat_session_id)
            "#,
        );

        query
            .push(" WHERE cs.user_id = ")
            .push_bind(Uuid::from(user.id))
            .generate_pagination("cl.compat_sso_login_id", pagination);

        let edges: Vec<CompatSsoLoginLookup> = query
            .build_query_as()
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(CompatSsoLogin::try_from)?;
        Ok(page)
    }
}
