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

use chrono::{DateTime, Duration, Utc};
use mas_data_model::{
    CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
    CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device, User,
};
use rand::Rng;
use sqlx::{Acquire, PgExecutor, Postgres, QueryBuilder};
use tracing::{info_span, Instrument};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    pagination::{process_page, QueryBuilderExt},
    Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt,
};

struct CompatSessionLookup {
    compat_session_id: Uuid,
    device_id: String,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

#[tracing::instrument(skip_all, err)]
pub async fn lookup_compat_session(
    executor: impl PgExecutor<'_>,
    session_id: Ulid,
) -> Result<Option<CompatSession>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatSessionLookup,
        r#"
            SELECT compat_session_id
                 , device_id
                 , user_id
                 , created_at
                 , finished_at
            FROM compat_sessions
            WHERE compat_session_id = $1
        "#,
        Uuid::from(session_id),
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let id = res.compat_session_id.into();
    let device = Device::try_from(res.device_id).map_err(|e| {
        DatabaseInconsistencyError::on("compat_sessions")
            .column("device_id")
            .row(id)
            .source(e)
    })?;

    let state = match res.finished_at {
        None => CompatSessionState::Valid,
        Some(finished_at) => CompatSessionState::Finished { finished_at },
    };

    let session = CompatSession {
        id,
        state,
        user_id: res.user_id.into(),
        device,
        created_at: res.created_at,
    };

    Ok(Some(session))
}

struct CompatAccessTokenLookup {
    compat_access_token_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    compat_session_id: Uuid,
}

impl From<CompatAccessTokenLookup> for CompatAccessToken {
    fn from(value: CompatAccessTokenLookup) -> Self {
        Self {
            id: value.compat_access_token_id.into(),
            session_id: value.compat_session_id.into(),
            token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn find_compat_access_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<Option<CompatAccessToken>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatAccessTokenLookup,
        r#"
            SELECT compat_access_token_id
                 , access_token
                 , created_at
                 , expires_at
                 , compat_session_id

            FROM compat_access_tokens

            WHERE access_token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_access_token.id = %id,
    ),
    err,
)]
pub async fn lookup_compat_access_token(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<Option<CompatAccessToken>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatAccessTokenLookup,
        r#"
            SELECT compat_access_token_id
                 , access_token
                 , created_at
                 , expires_at
                 , compat_session_id

            FROM compat_access_tokens

            WHERE compat_access_token_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.into()))
}

pub struct CompatRefreshTokenLookup {
    compat_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    compat_access_token_id: Uuid,
    compat_session_id: Uuid,
}

#[tracing::instrument(skip_all, err)]
#[allow(clippy::type_complexity)]
pub async fn find_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<Option<CompatRefreshToken>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatRefreshTokenLookup,
        r#"
            SELECT compat_refresh_token_id
                 , refresh_token
                 , created_at
                 , consumed_at
                 , compat_session_id
                 , compat_access_token_id

            FROM compat_refresh_tokens

            WHERE refresh_token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None); };

    let state = match res.consumed_at {
        None => CompatRefreshTokenState::Valid,
        Some(consumed_at) => CompatRefreshTokenState::Consumed { consumed_at },
    };

    let refresh_token = CompatRefreshToken {
        id: res.compat_refresh_token_id.into(),
        state,
        session_id: res.compat_session_id.into(),
        access_token_id: res.compat_access_token_id.into(),
        token: res.refresh_token,
        created_at: res.created_at,
    };

    Ok(Some(refresh_token))
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_session.id = %session.id,
        compat_session.device.id = session.device.as_str(),
        compat_access_token.id,
        user.id = %session.user_id,
    ),
    err,
)]
pub async fn add_compat_access_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &CompatSession,
    token: String,
    expires_after: Option<Duration>,
) -> Result<CompatAccessToken, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_access_token.id", tracing::field::display(id));

    let expires_at = expires_after.map(|expires_after| created_at + expires_after);

    sqlx::query!(
        r#"
            INSERT INTO compat_access_tokens
                (compat_access_token_id, compat_session_id, access_token, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        token,
        created_at,
        expires_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat access token"))
    .await?;

    Ok(CompatAccessToken {
        id,
        session_id: session.id,
        token,
        created_at,
        expires_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_access_token.id = %access_token.id,
    ),
    err,
)]
pub async fn expire_compat_access_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    access_token: CompatAccessToken,
) -> Result<(), DatabaseError> {
    let expires_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE compat_access_tokens
            SET expires_at = $2
            WHERE compat_access_token_id = $1
        "#,
        Uuid::from(access_token.id),
        expires_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_session.id = %session.id,
        compat_session.device.id = session.device.as_str(),
        compat_access_token.id = %access_token.id,
        compat_refresh_token.id,
        user.id = %session.user_id,
    ),
    err,
)]
pub async fn add_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    session: &CompatSession,
    access_token: &CompatAccessToken,
    token: String,
) -> Result<CompatRefreshToken, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_refresh_token.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO compat_refresh_tokens
                (compat_refresh_token_id, compat_session_id,
                 compat_access_token_id, refresh_token, created_at)
            VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::from(id),
        Uuid::from(session.id),
        Uuid::from(access_token.id),
        token,
        created_at,
    )
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat refresh token"))
    .await?;

    Ok(CompatRefreshToken {
        id,
        state: CompatRefreshTokenState::default(),
        session_id: session.id,
        access_token_id: access_token.id,
        token,
        created_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(%compat_session.id),
    err,
)]
pub async fn end_compat_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    compat_session: CompatSession,
) -> Result<CompatSession, DatabaseError> {
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
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)?;

    let compat_session = compat_session
        .finish(finished_at)
        .map_err(DatabaseError::to_invalid_operation)?;

    Ok(compat_session)
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_refresh_token.id = %refresh_token.id,
    ),
    err,
)]
pub async fn consume_compat_refresh_token(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    refresh_token: CompatRefreshToken,
) -> Result<(), DatabaseError> {
    let consumed_at = clock.now();
    let res = sqlx::query!(
        r#"
            UPDATE compat_refresh_tokens
            SET consumed_at = $2
            WHERE compat_refresh_token_id = $1
        "#,
        Uuid::from(refresh_token.id),
        consumed_at,
    )
    .execute(executor)
    .await?;

    DatabaseError::ensure_affected_rows(&res, 1)
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_sso_login.id,
        compat_sso_login.redirect_uri = %redirect_uri,
    ),
    err,
)]
pub async fn insert_compat_sso_login(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    login_token: String,
    redirect_uri: Url,
) -> Result<CompatSsoLogin, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
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
    .execute(executor)
    .instrument(tracing::info_span!("Insert compat SSO login"))
    .await?;

    Ok(CompatSsoLogin {
        id,
        login_token,
        redirect_uri,
        created_at,
        state: CompatSsoLoginState::Pending,
    })
}

#[derive(sqlx::FromRow)]
struct CompatSsoLoginLookup {
    compat_sso_login_id: Uuid,
    compat_sso_login_token: String,
    compat_sso_login_redirect_uri: String,
    compat_sso_login_created_at: DateTime<Utc>,
    compat_sso_login_fulfilled_at: Option<DateTime<Utc>>,
    compat_sso_login_exchanged_at: Option<DateTime<Utc>>,
    compat_session_id: Option<Uuid>,
}

impl TryFrom<CompatSsoLoginLookup> for CompatSsoLogin {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: CompatSsoLoginLookup) -> Result<Self, Self::Error> {
        let id = res.compat_sso_login_id.into();
        let redirect_uri = Url::parse(&res.compat_sso_login_redirect_uri).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sso_logins")
                .column("redirect_uri")
                .row(id)
                .source(e)
        })?;

        let state = match (
            res.compat_sso_login_fulfilled_at,
            res.compat_sso_login_exchanged_at,
            res.compat_session_id,
        ) {
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
            login_token: res.compat_sso_login_token,
            redirect_uri,
            created_at: res.compat_sso_login_created_at,
            state,
        })
    }
}

#[tracing::instrument(
    skip_all,
    fields(
        compat_sso_login.id = %id,
    ),
    err,
)]
pub async fn get_compat_sso_login_by_id(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<Option<CompatSsoLogin>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT cl.compat_sso_login_id
                 , cl.login_token     AS "compat_sso_login_token"
                 , cl.redirect_uri    AS "compat_sso_login_redirect_uri"
                 , cl.created_at      AS "compat_sso_login_created_at"
                 , cl.fulfilled_at    AS "compat_sso_login_fulfilled_at"
                 , cl.exchanged_at    AS "compat_sso_login_exchanged_at"
                 , cl.compat_session_id AS "compat_session_id"

            FROM compat_sso_logins cl
            WHERE cl.compat_sso_login_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.try_into()?))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %user.username,
    ),
    err,
)]
pub async fn get_paginated_user_compat_sso_logins(
    executor: impl PgExecutor<'_>,
    user: &User,
    before: Option<Ulid>,
    after: Option<Ulid>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(bool, bool, Vec<CompatSsoLogin>), DatabaseError> {
    let mut query = QueryBuilder::new(
        r#"
            SELECT cl.compat_sso_login_id
                 , cl.login_token     AS "compat_sso_login_token"
                 , cl.redirect_uri    AS "compat_sso_login_redirect_uri"
                 , cl.created_at      AS "compat_sso_login_created_at"
                 , cl.fulfilled_at    AS "compat_sso_login_fulfilled_at"
                 , cl.exchanged_at    AS "compat_sso_login_exchanged_at"
                 , cl.compat_session_id AS "compat_session_id"
            FROM compat_sso_logins cl
        "#,
    );

    query
        .push(" WHERE cs.user_id = ")
        .push_bind(Uuid::from(user.id))
        .generate_pagination("cl.compat_sso_login_id", before, after, first, last)?;

    let span = info_span!(
        "Fetch paginated user compat SSO logins",
        db.statement = query.sql()
    );
    let page: Vec<CompatSsoLoginLookup> = query
        .build_query_as()
        .fetch_all(executor)
        .instrument(span)
        .await?;

    let (has_previous_page, has_next_page, page) = process_page(page, first, last)?;

    let page: Result<Vec<_>, _> = page.into_iter().map(TryInto::try_into).collect();
    Ok((has_previous_page, has_next_page, page?))
}

#[tracing::instrument(skip_all, err)]
pub async fn get_compat_sso_login_by_token(
    executor: impl PgExecutor<'_>,
    token: &str,
) -> Result<Option<CompatSsoLogin>, DatabaseError> {
    let res = sqlx::query_as!(
        CompatSsoLoginLookup,
        r#"
            SELECT cl.compat_sso_login_id
                 , cl.login_token     AS "compat_sso_login_token"
                 , cl.redirect_uri    AS "compat_sso_login_redirect_uri"
                 , cl.created_at      AS "compat_sso_login_created_at"
                 , cl.fulfilled_at    AS "compat_sso_login_fulfilled_at"
                 , cl.exchanged_at    AS "compat_sso_login_exchanged_at"
                 , cl.compat_session_id AS "compat_session_id"
            FROM compat_sso_logins cl
            WHERE cl.login_token = $1
        "#,
        token,
    )
    .fetch_one(executor)
    .instrument(tracing::info_span!("Lookup compat SSO login"))
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.try_into()?))
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        compat_session.id,
        compat_session.device.id = device.as_str(),
    ),
    err,
)]
pub async fn start_compat_session(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: &User,
    device: Device,
) -> Result<CompatSession, DatabaseError> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("compat_session.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO compat_sessions (compat_session_id, user_id, device_id, created_at)
            VALUES ($1, $2, $3, $4)
        "#,
        Uuid::from(id),
        Uuid::from(user.id),
        device.as_str(),
        created_at,
    )
    .execute(executor)
    .await?;

    Ok(CompatSession {
        id,
        state: CompatSessionState::default(),
        user_id: user.id,
        device,
        created_at,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        %user.id,
        %compat_sso_login.id,
        %compat_sso_login.redirect_uri,
        compat_session.id,
        compat_session.device.id = device.as_str(),
    ),
    err,
)]
pub async fn fullfill_compat_sso_login(
    conn: impl Acquire<'_, Database = Postgres> + Send,
    mut rng: impl Rng + Send,
    clock: &Clock,
    user: &User,
    compat_sso_login: CompatSsoLogin,
    device: Device,
) -> Result<CompatSsoLogin, DatabaseError> {
    if !matches!(compat_sso_login.state, CompatSsoLoginState::Pending) {
        return Err(DatabaseError::invalid_operation());
    };

    let mut txn = conn.begin().await?;

    let session = start_compat_session(&mut txn, &mut rng, clock, user, device).await?;
    let session_id = session.id;

    let fulfilled_at = clock.now();
    let compat_sso_login = compat_sso_login
        .fulfill(fulfilled_at, &session)
        .map_err(DatabaseError::to_invalid_operation)?;
    sqlx::query!(
        r#"
            UPDATE compat_sso_logins
            SET
                compat_session_id = $2,
                fulfilled_at = $3
            WHERE
                compat_sso_login_id = $1
        "#,
        Uuid::from(compat_sso_login.id),
        Uuid::from(session_id),
        fulfilled_at,
    )
    .execute(&mut txn)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await?;

    txn.commit().await?;

    Ok(compat_sso_login)
}

#[tracing::instrument(
    skip_all,
    fields(
        %compat_sso_login.id,
        %compat_sso_login.redirect_uri,
    ),
    err,
)]
pub async fn mark_compat_sso_login_as_exchanged(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    compat_sso_login: CompatSsoLogin,
) -> Result<CompatSsoLogin, DatabaseError> {
    let exchanged_at = clock.now();
    let compat_sso_login = compat_sso_login
        .exchange(exchanged_at)
        .map_err(DatabaseError::to_invalid_operation)?;

    sqlx::query!(
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
    .execute(executor)
    .instrument(tracing::info_span!("Update compat SSO login"))
    .await?;

    Ok(compat_sso_login)
}
