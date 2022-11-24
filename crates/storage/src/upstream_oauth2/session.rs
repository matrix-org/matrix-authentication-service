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

use chrono::{DateTime, Utc};
use mas_data_model::{UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProvider};
use rand::Rng;
use sqlx::PgExecutor;
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;

use crate::{Clock, DatabaseInconsistencyError, GenericLookupError, LookupError};

#[derive(Debug, Error)]
#[error("Failed to lookup upstream OAuth 2.0 authorization session")]
pub enum SessionLookupError {
    Driver(#[from] sqlx::Error),
    Inconcistency(#[from] DatabaseInconsistencyError),
}

impl LookupError for SessionLookupError {
    fn not_found(&self) -> bool {
        matches!(self, Self::Driver(sqlx::Error::RowNotFound))
    }
}

struct SessionAndProviderLookup {
    upstream_oauth_authorization_session_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: String,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    provider_issuer: String,
    provider_scope: String,
    provider_client_id: String,
    provider_encrypted_client_secret: Option<String>,
    provider_token_endpoint_auth_method: String,
    provider_token_endpoint_signing_alg: Option<String>,
    provider_created_at: DateTime<Utc>,
}

/// Lookup a session and its provider by its ID
#[tracing::instrument(
    skip_all,
    fields(upstream_oauth_authorization_session.id = %id),
    err,
)]
pub async fn lookup_session(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<(UpstreamOAuthProvider, UpstreamOAuthAuthorizationSession), SessionLookupError> {
    let res = sqlx::query_as!(
        SessionAndProviderLookup,
        r#"
            SELECT
                ua.upstream_oauth_authorization_session_id,
                ua.upstream_oauth_provider_id,
                ua.state,
                ua.code_challenge_verifier,
                ua.nonce,
                ua.created_at,
                ua.completed_at,
                ua.consumed_at,
                up.issuer AS "provider_issuer",
                up.scope AS "provider_scope",
                up.client_id AS "provider_client_id",
                up.encrypted_client_secret AS "provider_encrypted_client_secret",
                up.token_endpoint_auth_method AS "provider_token_endpoint_auth_method",
                up.token_endpoint_signing_alg AS "provider_token_endpoint_signing_alg",
                up.created_at AS "provider_created_at"
            FROM upstream_oauth_authorization_sessions ua
            INNER JOIN upstream_oauth_providers up
              USING (upstream_oauth_provider_id)
            WHERE upstream_oauth_authorization_session_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .await?;

    let provider = UpstreamOAuthProvider {
        id: res.upstream_oauth_provider_id.into(),
        issuer: res
            .provider_issuer
            .parse()
            .map_err(|_| DatabaseInconsistencyError)?,
        scope: res
            .provider_scope
            .parse()
            .map_err(|_| DatabaseInconsistencyError)?,
        client_id: res.provider_client_id,
        encrypted_client_secret: res.provider_encrypted_client_secret,
        token_endpoint_auth_method: res
            .provider_token_endpoint_auth_method
            .parse()
            .map_err(|_| DatabaseInconsistencyError)?,
        token_endpoint_signing_alg: res
            .provider_token_endpoint_signing_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|_| DatabaseInconsistencyError)?,
        created_at: res.provider_created_at,
    };

    let session = UpstreamOAuthAuthorizationSession {
        id: res.upstream_oauth_authorization_session_id.into(),
        state: res.state,
        code_challenge_verifier: res.code_challenge_verifier,
        nonce: res.nonce,
        created_at: res.created_at,
        completed_at: res.completed_at,
        consumed_at: res.consumed_at,
    };

    Ok((provider, session))
}

/// Add a session to the database
#[tracing::instrument(
    skip_all,
    fields(
        %upstream_oauth_provider.id,
        %upstream_oauth_provider.issuer,
        %upstream_oauth_provider.client_id,
        upstream_oauth_authorization_session.id,
    ),
    err,
)]
pub async fn add_session(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    upstream_oauth_provider: &UpstreamOAuthProvider,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: String,
) -> Result<UpstreamOAuthAuthorizationSession, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record(
        "upstream_oauth_authorization_session.id",
        tracing::field::display(id),
    );

    sqlx::query!(
        r#"
            INSERT INTO upstream_oauth_authorization_sessions (
                upstream_oauth_authorization_session_id,
                upstream_oauth_provider_id,
                state,
                code_challenge_verifier,
                nonce,
                created_at,
                completed_at,
                consumed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL)
        "#,
        Uuid::from(id),
        Uuid::from(upstream_oauth_provider.id),
        &state,
        code_challenge_verifier.as_deref(),
        nonce,
        created_at,
    )
    .execute(executor)
    .await?;

    Ok(UpstreamOAuthAuthorizationSession {
        id,
        state,
        code_challenge_verifier,
        nonce,
        created_at,
        completed_at: None,
        consumed_at: None,
    })
}

/// Mark a session as completed and associate the given link
#[tracing::instrument(
    skip_all,
    fields(
        %upstream_oauth_authorization_session.id,
        %upstream_oauth_link.id,
    ),
    err,
)]
pub async fn complete_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    upstream_oauth_link: &UpstreamOAuthLink,
) -> Result<UpstreamOAuthAuthorizationSession, sqlx::Error> {
    let completed_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE upstream_oauth_authorization_sessions
            SET upstream_oauth_link_id = $1,
                completed_at = $2
            WHERE upstream_oauth_authorization_session_id = $3
        "#,
        Uuid::from(upstream_oauth_link.id),
        completed_at,
        Uuid::from(upstream_oauth_authorization_session.id),
    )
    .execute(executor)
    .await?;

    upstream_oauth_authorization_session.completed_at = Some(completed_at);

    Ok(upstream_oauth_authorization_session)
}

/// Mark a session as consumed
#[tracing::instrument(
    skip_all,
    fields(
        %upstream_oauth_authorization_session.id,
    ),
    err,
)]
pub async fn consume_session(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
) -> Result<UpstreamOAuthAuthorizationSession, sqlx::Error> {
    let consumed_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE upstream_oauth_authorization_sessions
            SET consumed_at = $1
            WHERE upstream_oauth_authorization_session_id = $2
        "#,
        consumed_at,
        Uuid::from(upstream_oauth_authorization_session.id),
    )
    .execute(executor)
    .await?;

    upstream_oauth_authorization_session.consumed_at = Some(consumed_at);

    Ok(upstream_oauth_authorization_session)
}

struct SessionLookup {
    upstream_oauth_authorization_session_id: Uuid,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: String,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
}

/// Lookup a session, which belongs to a link, by its ID
#[tracing::instrument(
    skip_all,
    fields(
        upstream_oauth_authorization_session.id = %id,
        %upstream_oauth_link.id,
    ),
    err,
)]
pub async fn lookup_session_on_link(
    executor: impl PgExecutor<'_>,
    upstream_oauth_link: &UpstreamOAuthLink,
    id: Ulid,
) -> Result<UpstreamOAuthAuthorizationSession, GenericLookupError> {
    let res = sqlx::query_as!(
        SessionLookup,
        r#"
            SELECT
                upstream_oauth_authorization_session_id,
                state,
                code_challenge_verifier,
                nonce,
                created_at,
                completed_at,
                consumed_at
            FROM upstream_oauth_authorization_sessions
            WHERE upstream_oauth_authorization_session_id = $1
              AND upstream_oauth_link_id = $2
        "#,
        Uuid::from(id),
        Uuid::from(upstream_oauth_link.id),
    )
    .fetch_one(executor)
    .await
    .map_err(GenericLookupError::what(
        "Upstream OAuth 2.0 session on link",
    ))?;

    Ok(UpstreamOAuthAuthorizationSession {
        id: res.upstream_oauth_authorization_session_id.into(),
        state: res.state,
        code_challenge_verifier: res.code_challenge_verifier,
        nonce: res.nonce,
        created_at: res.created_at,
        completed_at: res.completed_at,
        consumed_at: res.consumed_at,
    })
}
