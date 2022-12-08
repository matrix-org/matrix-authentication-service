// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use mas_data_model::{
    Authentication, AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, BrowserSession,
    Client, Pkce, Session, User, UserEmail,
};
use mas_iana::oauth::PkceCodeChallengeMethod;
use oauth2_types::{requests::ResponseMode, scope::Scope};
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use super::client::lookup_client;
use crate::{Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt};

#[tracing::instrument(
    skip_all,
    fields(
        %client.id,
        grant.id,
    ),
    err,
)]
#[allow(clippy::too_many_arguments)]
pub async fn new_authorization_grant(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    client: Client,
    redirect_uri: Url,
    scope: Scope,
    code: Option<AuthorizationCode>,
    state: Option<String>,
    nonce: Option<String>,
    max_age: Option<NonZeroU32>,
    _acr_values: Option<String>,
    response_mode: ResponseMode,
    response_type_id_token: bool,
    requires_consent: bool,
) -> Result<AuthorizationGrant, sqlx::Error> {
    let code_challenge = code
        .as_ref()
        .and_then(|c| c.pkce.as_ref())
        .map(|p| &p.challenge);
    let code_challenge_method = code
        .as_ref()
        .and_then(|c| c.pkce.as_ref())
        .map(|p| p.challenge_method.to_string());
    // TODO: this conversion is a bit ugly
    let max_age_i32 = max_age.map(|x| i32::try_from(u32::from(x)).unwrap_or(i32::MAX));
    let code_str = code.as_ref().map(|c| &c.code);

    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("grant.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_authorization_grants (
                 oauth2_authorization_grant_id,
                 oauth2_client_id,
                 redirect_uri,
                 scope,
                 state,
                 nonce,
                 max_age,
                 response_mode,
                 code_challenge,
                 code_challenge_method,
                 response_type_code,
                 response_type_id_token,
                 authorization_code,
                 requires_consent,
                 created_at
            )
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
        Uuid::from(id),
        Uuid::from(client.id),
        redirect_uri.to_string(),
        scope.to_string(),
        state,
        nonce,
        max_age_i32,
        response_mode.to_string(),
        code_challenge,
        code_challenge_method,
        code.is_some(),
        response_type_id_token,
        code_str,
        requires_consent,
        created_at,
    )
    .execute(executor)
    .await?;

    Ok(AuthorizationGrant {
        id,
        stage: AuthorizationGrantStage::Pending,
        code,
        redirect_uri,
        client,
        scope,
        state,
        nonce,
        max_age,
        response_mode,
        created_at,
        response_type_id_token,
        requires_consent,
    })
}

#[allow(clippy::struct_excessive_bools)]
struct GrantLookup {
    oauth2_authorization_grant_id: Uuid,
    oauth2_authorization_grant_created_at: DateTime<Utc>,
    oauth2_authorization_grant_cancelled_at: Option<DateTime<Utc>>,
    oauth2_authorization_grant_fulfilled_at: Option<DateTime<Utc>>,
    oauth2_authorization_grant_exchanged_at: Option<DateTime<Utc>>,
    oauth2_authorization_grant_scope: String,
    oauth2_authorization_grant_state: Option<String>,
    oauth2_authorization_grant_nonce: Option<String>,
    oauth2_authorization_grant_redirect_uri: String,
    oauth2_authorization_grant_response_mode: String,
    oauth2_authorization_grant_max_age: Option<i32>,
    oauth2_authorization_grant_response_type_code: bool,
    oauth2_authorization_grant_response_type_id_token: bool,
    oauth2_authorization_grant_code: Option<String>,
    oauth2_authorization_grant_code_challenge: Option<String>,
    oauth2_authorization_grant_code_challenge_method: Option<String>,
    oauth2_authorization_grant_requires_consent: bool,
    oauth2_client_id: Uuid,
    oauth2_session_id: Option<Uuid>,
    user_session_id: Option<Uuid>,
    user_session_created_at: Option<DateTime<Utc>>,
    user_id: Option<Uuid>,
    user_username: Option<String>,
    user_session_last_authentication_id: Option<Uuid>,
    user_session_last_authentication_created_at: Option<DateTime<Utc>>,
    user_email_id: Option<Uuid>,
    user_email: Option<String>,
    user_email_created_at: Option<DateTime<Utc>>,
    user_email_confirmed_at: Option<DateTime<Utc>>,
}

impl GrantLookup {
    #[allow(clippy::too_many_lines)]
    async fn into_authorization_grant(
        self,
        executor: impl PgExecutor<'_>,
    ) -> Result<AuthorizationGrant, DatabaseError> {
        let id = self.oauth2_authorization_grant_id.into();
        let scope: Scope = self.oauth2_authorization_grant_scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        // TODO: don't unwrap
        let client = lookup_client(executor, self.oauth2_client_id.into())
            .await?
            .ok_or_else(|| {
                DatabaseInconsistencyError::on("oauth2_authorization_grants")
                    .column("client_id")
                    .row(id)
            })?;

        let last_authentication = match (
            self.user_session_last_authentication_id,
            self.user_session_last_authentication_created_at,
        ) {
            (Some(id), Some(created_at)) => Some(Authentication {
                id: id.into(),
                created_at,
            }),
            (None, None) => None,
            _ => return Err(DatabaseInconsistencyError::on("user_session_authentications").into()),
        };

        let primary_email = match (
            self.user_email_id,
            self.user_email,
            self.user_email_created_at,
            self.user_email_confirmed_at,
        ) {
            (Some(id), Some(email), Some(created_at), confirmed_at) => Some(UserEmail {
                id: id.into(),
                email,
                created_at,
                confirmed_at,
            }),
            (None, None, None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on("users")
                    .column("primary_user_email_id")
                    .into())
            }
        };

        let session = match (
            self.oauth2_session_id,
            self.user_session_id,
            self.user_session_created_at,
            self.user_id,
            self.user_username,
            last_authentication,
            primary_email,
        ) {
            (
                Some(session_id),
                Some(user_session_id),
                Some(user_session_created_at),
                Some(user_id),
                Some(user_username),
                last_authentication,
                primary_email,
            ) => {
                let user_id = Ulid::from(user_id);
                let user = User {
                    id: user_id,
                    username: user_username,
                    sub: user_id.to_string(),
                    primary_email,
                };

                let browser_session = BrowserSession {
                    id: user_session_id.into(),
                    user,
                    created_at: user_session_created_at,
                    last_authentication,
                };

                let client = client.clone();
                let scope = scope.clone();

                let session = Session {
                    id: session_id.into(),
                    client,
                    browser_session,
                    scope,
                };

                Some(session)
            }
            (None, None, None, None, None, None, None) => None,
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("oauth2_session_id")
                        .row(id)
                        .into(),
                )
            }
        };

        let stage = match (
            self.oauth2_authorization_grant_fulfilled_at,
            self.oauth2_authorization_grant_exchanged_at,
            self.oauth2_authorization_grant_cancelled_at,
            session,
        ) {
            (None, None, None, None) => AuthorizationGrantStage::Pending,
            (Some(fulfilled_at), None, None, Some(session)) => AuthorizationGrantStage::Fulfilled {
                session,
                fulfilled_at,
            },
            (Some(fulfilled_at), Some(exchanged_at), None, Some(session)) => {
                AuthorizationGrantStage::Exchanged {
                    session,
                    fulfilled_at,
                    exchanged_at,
                }
            }
            (None, None, Some(cancelled_at), None) => {
                AuthorizationGrantStage::Cancelled { cancelled_at }
            }
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("stage")
                        .row(id)
                        .into(),
                );
            }
        };

        let pkce = match (
            self.oauth2_authorization_grant_code_challenge,
            self.oauth2_authorization_grant_code_challenge_method,
        ) {
            (Some(challenge), Some(challenge_method)) if challenge_method == "plain" => {
                Some(Pkce {
                    challenge_method: PkceCodeChallengeMethod::Plain,
                    challenge,
                })
            }
            (Some(challenge), Some(challenge_method)) if challenge_method == "S256" => Some(Pkce {
                challenge_method: PkceCodeChallengeMethod::S256,
                challenge,
            }),
            (None, None) => None,
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("code_challenge_method")
                        .row(id)
                        .into(),
                );
            }
        };

        let code: Option<AuthorizationCode> = match (
            self.oauth2_authorization_grant_response_type_code,
            self.oauth2_authorization_grant_code,
            pkce,
        ) {
            (false, None, None) => None,
            (true, Some(code), pkce) => Some(AuthorizationCode { code, pkce }),
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("authorization_code")
                        .row(id)
                        .into(),
                );
            }
        };

        let redirect_uri = self
            .oauth2_authorization_grant_redirect_uri
            .parse()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_authorization_grants")
                    .column("redirect_uri")
                    .row(id)
                    .source(e)
            })?;

        let response_mode = self
            .oauth2_authorization_grant_response_mode
            .parse()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_authorization_grants")
                    .column("response_mode")
                    .row(id)
                    .source(e)
            })?;

        let max_age = self
            .oauth2_authorization_grant_max_age
            .map(u32::try_from)
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_authorization_grants")
                    .column("max_age")
                    .row(id)
                    .source(e)
            })?
            .map(NonZeroU32::try_from)
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_authorization_grants")
                    .column("max_age")
                    .row(id)
                    .source(e)
            })?;

        Ok(AuthorizationGrant {
            id,
            stage,
            client,
            code,
            scope,
            state: self.oauth2_authorization_grant_state,
            nonce: self.oauth2_authorization_grant_nonce,
            max_age,
            response_mode,
            redirect_uri,
            created_at: self.oauth2_authorization_grant_created_at,
            response_type_id_token: self.oauth2_authorization_grant_response_type_id_token,
            requires_consent: self.oauth2_authorization_grant_requires_consent,
        })
    }
}

#[tracing::instrument(
    skip_all,
    fields(grant.id = %id),
    err,
)]
pub async fn get_grant_by_id(
    conn: &mut PgConnection,
    id: Ulid,
) -> Result<Option<AuthorizationGrant>, DatabaseError> {
    let res = sqlx::query_as!(
        GrantLookup,
        r#"
            SELECT
                og.oauth2_authorization_grant_id,
                og.created_at              AS oauth2_authorization_grant_created_at,
                og.cancelled_at            AS oauth2_authorization_grant_cancelled_at,
                og.fulfilled_at            AS oauth2_authorization_grant_fulfilled_at,
                og.exchanged_at            AS oauth2_authorization_grant_exchanged_at,
                og.scope                   AS oauth2_authorization_grant_scope,
                og.state                   AS oauth2_authorization_grant_state,
                og.redirect_uri            AS oauth2_authorization_grant_redirect_uri,
                og.response_mode           AS oauth2_authorization_grant_response_mode,
                og.nonce                   AS oauth2_authorization_grant_nonce,
                og.max_age                 AS oauth2_authorization_grant_max_age,
                og.oauth2_client_id        AS oauth2_client_id,
                og.authorization_code      AS oauth2_authorization_grant_code,
                og.response_type_code      AS oauth2_authorization_grant_response_type_code,
                og.response_type_id_token  AS oauth2_authorization_grant_response_type_id_token,
                og.code_challenge          AS oauth2_authorization_grant_code_challenge,
                og.code_challenge_method   AS oauth2_authorization_grant_code_challenge_method,
                og.requires_consent        AS oauth2_authorization_grant_requires_consent,
                os.oauth2_session_id       AS "oauth2_session_id?",
                us.user_session_id         AS "user_session_id?",
                us.created_at              AS "user_session_created_at?",
                 u.user_id                 AS "user_id?",
                 u.username                AS "user_username?",
                usa.user_session_authentication_id AS "user_session_last_authentication_id?",
                usa.created_at             AS "user_session_last_authentication_created_at?",
                ue.user_email_id           AS "user_email_id?",
                ue.email                   AS "user_email?",
                ue.created_at              AS "user_email_created_at?",
                ue.confirmed_at            AS "user_email_confirmed_at?"
            FROM
                oauth2_authorization_grants og
            LEFT JOIN oauth2_sessions os
              USING (oauth2_session_id)
            LEFT JOIN user_sessions us
              USING (user_session_id)
            LEFT JOIN users u
              USING (user_id)
            LEFT JOIN user_session_authentications usa
              USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

            WHERE og.oauth2_authorization_grant_id = $1

            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        Uuid::from(id),
    )
    .fetch_one(&mut *conn)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let grant = res.into_authorization_grant(&mut *conn).await?;

    Ok(Some(grant))
}

#[tracing::instrument(skip_all, err)]
pub async fn lookup_grant_by_code(
    conn: &mut PgConnection,
    code: &str,
) -> Result<Option<AuthorizationGrant>, DatabaseError> {
    let res = sqlx::query_as!(
        GrantLookup,
        r#"
            SELECT
                og.oauth2_authorization_grant_id,
                og.created_at              AS oauth2_authorization_grant_created_at,
                og.cancelled_at            AS oauth2_authorization_grant_cancelled_at,
                og.fulfilled_at            AS oauth2_authorization_grant_fulfilled_at,
                og.exchanged_at            AS oauth2_authorization_grant_exchanged_at,
                og.scope                   AS oauth2_authorization_grant_scope,
                og.state                   AS oauth2_authorization_grant_state,
                og.redirect_uri            AS oauth2_authorization_grant_redirect_uri,
                og.response_mode           AS oauth2_authorization_grant_response_mode,
                og.nonce                   AS oauth2_authorization_grant_nonce,
                og.max_age                 AS oauth2_authorization_grant_max_age,
                og.oauth2_client_id        AS oauth2_client_id,
                og.authorization_code      AS oauth2_authorization_grant_code,
                og.response_type_code      AS oauth2_authorization_grant_response_type_code,
                og.response_type_id_token  AS oauth2_authorization_grant_response_type_id_token,
                og.code_challenge          AS oauth2_authorization_grant_code_challenge,
                og.code_challenge_method   AS oauth2_authorization_grant_code_challenge_method,
                og.requires_consent        AS oauth2_authorization_grant_requires_consent,
                os.oauth2_session_id       AS "oauth2_session_id?",
                us.user_session_id         AS "user_session_id?",
                us.created_at              AS "user_session_created_at?",
                 u.user_id                 AS "user_id?",
                 u.username                AS "user_username?",
                usa.user_session_authentication_id AS "user_session_last_authentication_id?",
                usa.created_at             AS "user_session_last_authentication_created_at?",
                ue.user_email_id           AS "user_email_id?",
                ue.email                   AS "user_email?",
                ue.created_at              AS "user_email_created_at?",
                ue.confirmed_at            AS "user_email_confirmed_at?"
            FROM
                oauth2_authorization_grants og
            LEFT JOIN oauth2_sessions os
              USING (oauth2_session_id)
            LEFT JOIN user_sessions us
              USING (user_session_id)
            LEFT JOIN users u
              USING (user_id)
            LEFT JOIN user_session_authentications usa
              USING (user_session_id)
            LEFT JOIN user_emails ue
              ON ue.user_email_id = u.primary_user_email_id

            WHERE og.authorization_code = $1

            ORDER BY usa.created_at DESC
            LIMIT 1
        "#,
        code,
    )
    .fetch_one(&mut *conn)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    let grant = res.into_authorization_grant(&mut *conn).await?;

    Ok(Some(grant))
}

#[tracing::instrument(
    skip_all,
    fields(
        %grant.id,
        client.id = %grant.client.id,
        session.id,
        user_session.id = %browser_session.id,
        user.id = %browser_session.user.id,
    ),
    err,
)]
pub async fn derive_session(
    executor: impl PgExecutor<'_>,
    mut rng: impl Rng + Send,
    clock: &Clock,
    grant: &AuthorizationGrant,
    browser_session: BrowserSession,
) -> Result<Session, sqlx::Error> {
    let created_at = clock.now();
    let id = Ulid::from_datetime_with_source(created_at.into(), &mut rng);
    tracing::Span::current().record("session.id", tracing::field::display(id));

    sqlx::query!(
        r#"
            INSERT INTO oauth2_sessions
                (oauth2_session_id, user_session_id, oauth2_client_id, scope, created_at)
            SELECT
                $1,
                $2,
                og.oauth2_client_id,
                og.scope,
                $3
            FROM
                oauth2_authorization_grants og
            WHERE
                og.oauth2_authorization_grant_id = $4
        "#,
        Uuid::from(id),
        Uuid::from(browser_session.id),
        created_at,
        Uuid::from(grant.id),
    )
    .execute(executor)
    .await?;

    Ok(Session {
        id,
        browser_session,
        client: grant.client.clone(),
        scope: grant.scope.clone(),
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        %grant.id,
        client.id = %grant.client.id,
        %session.id,
        user_session.id = %session.browser_session.id,
        user.id = %session.browser_session.user.id,
    ),
    err,
)]
pub async fn fulfill_grant(
    executor: impl PgExecutor<'_>,
    mut grant: AuthorizationGrant,
    session: Session,
) -> Result<AuthorizationGrant, DatabaseError> {
    let fulfilled_at = sqlx::query_scalar!(
        r#"
            UPDATE oauth2_authorization_grants AS og
            SET
                oauth2_session_id = os.oauth2_session_id,
                fulfilled_at = os.created_at
            FROM oauth2_sessions os
            WHERE
                og.oauth2_authorization_grant_id = $1
                AND os.oauth2_session_id = $2
            RETURNING fulfilled_at AS "fulfilled_at!: DateTime<Utc>"
        "#,
        Uuid::from(grant.id),
        Uuid::from(session.id),
    )
    .fetch_one(executor)
    .await?;

    grant.stage = grant
        .stage
        .fulfill(fulfilled_at, session)
        .map_err(DatabaseError::to_invalid_operation)?;

    Ok(grant)
}

#[tracing::instrument(
    skip_all,
    fields(
        %grant.id,
        client.id = %grant.client.id,
    ),
    err,
)]
pub async fn give_consent_to_grant(
    executor: impl PgExecutor<'_>,
    mut grant: AuthorizationGrant,
) -> Result<AuthorizationGrant, sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE oauth2_authorization_grants AS og
            SET
                requires_consent = 'f'
            WHERE
                og.oauth2_authorization_grant_id = $1
        "#,
        Uuid::from(grant.id),
    )
    .execute(executor)
    .await?;

    grant.requires_consent = false;

    Ok(grant)
}

#[tracing::instrument(
    skip_all,
    fields(
        %grant.id,
        client.id = %grant.client.id,
    ),
    err,
)]
pub async fn exchange_grant(
    executor: impl PgExecutor<'_>,
    clock: &Clock,
    mut grant: AuthorizationGrant,
) -> Result<AuthorizationGrant, DatabaseError> {
    let exchanged_at = clock.now();
    sqlx::query!(
        r#"
            UPDATE oauth2_authorization_grants
            SET exchanged_at = $2
            WHERE oauth2_authorization_grant_id = $1
        "#,
        Uuid::from(grant.id),
        exchanged_at,
    )
    .execute(executor)
    .await?;

    grant.stage = grant
        .stage
        .exchange(exchanged_at)
        .map_err(DatabaseError::to_invalid_operation)?;

    Ok(grant)
}
