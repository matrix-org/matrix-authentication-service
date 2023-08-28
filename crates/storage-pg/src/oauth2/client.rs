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

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    string::ToString,
};

use async_trait::async_trait;
use mas_data_model::{Client, JwksOrJwksUri, User};
use mas_iana::{
    jose::JsonWebSignatureAlg,
    oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
};
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_storage::{oauth2::OAuth2ClientRepository, Clock};
use oauth2_types::{
    oidc::ApplicationType,
    requests::GrantType,
    scope::{Scope, ScopeToken},
};
use rand::RngCore;
use sqlx::PgConnection;
use tracing::{info_span, Instrument};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`OAuth2ClientRepository`] for a PostgreSQL connection
pub struct PgOAuth2ClientRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2ClientRepository<'c> {
    /// Create a new [`PgOAuth2ClientRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

// XXX: response_types & contacts
#[derive(Debug)]
struct OAuth2ClientLookup {
    oauth2_client_id: Uuid,
    encrypted_client_secret: Option<String>,
    application_type: Option<String>,
    redirect_uris: Vec<String>,
    // response_types: Vec<String>,
    grant_type_authorization_code: bool,
    grant_type_refresh_token: bool,
    contacts: Vec<String>,
    client_name: Option<String>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    id_token_signed_response_alg: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    initiate_login_uri: Option<String>,
}

impl TryInto<Client> for OAuth2ClientLookup {
    type Error = DatabaseInconsistencyError;

    #[allow(clippy::too_many_lines)] // TODO: refactor some of the field parsing
    fn try_into(self) -> Result<Client, Self::Error> {
        let id = Ulid::from(self.oauth2_client_id);

        let redirect_uris: Result<Vec<Url>, _> =
            self.redirect_uris.iter().map(|s| s.parse()).collect();
        let redirect_uris = redirect_uris.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("redirect_uris")
                .row(id)
                .source(e)
        })?;

        let application_type = self
            .application_type
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("application_type")
                    .row(id)
                    .source(e)
            })?;

        let response_types = vec![
            OAuthAuthorizationEndpointResponseType::Code,
            OAuthAuthorizationEndpointResponseType::IdToken,
            OAuthAuthorizationEndpointResponseType::None,
        ];
        /* XXX
        let response_types: Result<Vec<OAuthAuthorizationEndpointResponseType>, _> =
            self.response_types.iter().map(|s| s.parse()).collect();
        let response_types = response_types.map_err(|source| ClientFetchError::ParseField {
            field: "response_types",
            source,
        })?;
        */

        let mut grant_types = Vec::new();
        if self.grant_type_authorization_code {
            grant_types.push(GrantType::AuthorizationCode);
        }
        if self.grant_type_refresh_token {
            grant_types.push(GrantType::RefreshToken);
        }

        let logo_uri = self.logo_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("logo_uri")
                .row(id)
                .source(e)
        })?;

        let client_uri = self
            .client_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("client_uri")
                    .row(id)
                    .source(e)
            })?;

        let policy_uri = self
            .policy_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("policy_uri")
                    .row(id)
                    .source(e)
            })?;

        let tos_uri = self.tos_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("tos_uri")
                .row(id)
                .source(e)
        })?;

        let id_token_signed_response_alg = self
            .id_token_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = self
            .userinfo_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_method = self
            .token_endpoint_auth_method
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_method")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_signing_alg = self
            .token_endpoint_auth_signing_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_signing_alg")
                    .row(id)
                    .source(e)
            })?;

        let initiate_login_uri = self
            .initiate_login_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("initiate_login_uri")
                    .row(id)
                    .source(e)
            })?;

        let jwks = match (self.jwks, self.jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => {
                let jwks = serde_json::from_value(jwks).map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks")
                        .row(id)
                        .source(e)
                })?;
                Some(JwksOrJwksUri::Jwks(jwks))
            }
            (None, Some(jwks_uri)) => {
                let jwks_uri = jwks_uri.parse().map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks_uri")
                        .row(id)
                        .source(e)
                })?;

                Some(JwksOrJwksUri::JwksUri(jwks_uri))
            }
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth2_clients")
                    .column("jwks(_uri)")
                    .row(id))
            }
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            encrypted_client_secret: self.encrypted_client_secret,
            application_type,
            redirect_uris,
            response_types,
            grant_types,
            contacts: self.contacts,
            client_name: self.client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }
}

#[async_trait]
impl<'c> OAuth2ClientRepository for PgOAuth2ClientRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_client.lookup",
        skip_all,
        fields(
            db.statement,
            oauth2_client.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , contacts
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c

                WHERE oauth2_client_id = $1
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
        name = "db.oauth2_client.load_batch",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error> {
        let ids: Vec<Uuid> = ids.into_iter().map(Uuid::from).collect();
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , contacts
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c

                WHERE oauth2_client_id = ANY($1::uuid[])
            "#,
            &ids,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        res.into_iter()
            .map(|r| {
                r.try_into()
                    .map(|c: Client| (c.id, c))
                    .map_err(DatabaseError::from)
            })
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.add",
        skip_all,
        fields(
            db.statement,
            client.id,
            client.name = client_name
        ),
        err,
    )]
    #[allow(clippy::too_many_lines)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        encrypted_client_secret: Option<String>,
        application_type: Option<ApplicationType>,
        grant_types: Vec<GrantType>,
        contacts: Vec<String>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("client.id", tracing::field::display(id));

        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_clients
                    ( oauth2_client_id
                    , encrypted_client_secret
                    , application_type
                    , redirect_uris
                    , grant_type_authorization_code
                    , grant_type_refresh_token
                    , client_name
                    , logo_uri
                    , client_uri
                    , policy_uri
                    , tos_uri
                    , jwks_uri
                    , jwks
                    , id_token_signed_response_alg
                    , userinfo_signed_response_alg
                    , token_endpoint_auth_method
                    , token_endpoint_auth_signing_alg
                    , initiate_login_uri
                    , is_static
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, FALSE)
            "#,
            Uuid::from(id),
            encrypted_client_secret,
            application_type.map(|a| a.to_string()),
            &redirect_uris_array,
            grant_types.contains(&GrantType::AuthorizationCode),
            grant_types.contains(&GrantType::RefreshToken),
            client_name,
            logo_uri.as_ref().map(Url::as_str),
            client_uri.as_ref().map(Url::as_str),
            policy_uri.as_ref().map(Url::as_str),
            tos_uri.as_ref().map(Url::as_str),
            jwks_uri.as_ref().map(Url::as_str),
            jwks_json,
            id_token_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_method.as_ref().map(ToString::to_string),
            token_endpoint_auth_signing_alg
                .as_ref()
                .map(ToString::to_string),
            initiate_login_uri.as_ref().map(Url::as_str),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            encrypted_client_secret,
            application_type,
            redirect_uris,
            response_types: vec![
                OAuthAuthorizationEndpointResponseType::Code,
                OAuthAuthorizationEndpointResponseType::IdToken,
                OAuthAuthorizationEndpointResponseType::None,
            ],
            grant_types,
            contacts,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.upsert_static",
        skip_all,
        fields(
            db.statement,
            client.id = %client_id,
        ),
        err,
    )]
    async fn upsert_static(
        &mut self,
        client_id: Ulid,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error> {
        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let client_auth_method = client_auth_method.to_string();
        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_clients
                    ( oauth2_client_id
                    , encrypted_client_secret
                    , redirect_uris
                    , grant_type_authorization_code
                    , grant_type_refresh_token
                    , token_endpoint_auth_method
                    , jwks
                    , jwks_uri
                    , is_static
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
                ON CONFLICT (oauth2_client_id)
                DO
                    UPDATE SET encrypted_client_secret = EXCLUDED.encrypted_client_secret
                             , grant_type_authorization_code = EXCLUDED.grant_type_authorization_code
                             , grant_type_refresh_token = EXCLUDED.grant_type_refresh_token
                             , token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method
                             , jwks = EXCLUDED.jwks
                             , jwks_uri = EXCLUDED.jwks_uri
                             , is_static = TRUE
            "#,
            Uuid::from(client_id),
            encrypted_client_secret,
            &redirect_uris_array,
            true,
            true,
            client_auth_method,
            jwks_json,
            jwks_uri.as_ref().map(Url::as_str),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id: client_id,
            client_id: client_id.to_string(),
            encrypted_client_secret,
            application_type: None,
            redirect_uris,
            response_types: vec![
                OAuthAuthorizationEndpointResponseType::Code,
                OAuthAuthorizationEndpointResponseType::IdToken,
                OAuthAuthorizationEndpointResponseType::None,
            ],
            grant_types: Vec::new(),
            contacts: Vec::new(),
            client_name: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks,
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            initiate_login_uri: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.all_static",
        skip_all,
        fields(
            db.statement,
        ),
        err,
    )]
    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , contacts
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c
                WHERE is_static = TRUE
            "#,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        res.into_iter()
            .map(|r| r.try_into().map_err(DatabaseError::from))
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.get_consent_for_user",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %client.id,
        ),
        err,
    )]
    async fn get_consent_for_user(
        &mut self,
        client: &Client,
        user: &User,
    ) -> Result<Scope, Self::Error> {
        let scope_tokens: Vec<String> = sqlx::query_scalar!(
            r#"
                SELECT scope_token
                FROM oauth2_consents
                WHERE user_id = $1 AND oauth2_client_id = $2
            "#,
            Uuid::from(user.id),
            Uuid::from(client.id),
        )
        .fetch_all(&mut *self.conn)
        .await?;

        let scope: Result<Scope, _> = scope_tokens
            .into_iter()
            .map(|s| ScopeToken::from_str(&s))
            .collect();

        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_consents")
                .column("scope_token")
                .source(e)
        })?;

        Ok(scope)
    }

    #[tracing::instrument(
        name = "db.oauth2_client.give_consent_for_user",
        skip_all,
        fields(
            db.statement,
            %user.id,
            %client.id,
            %scope,
        ),
        err,
    )]
    async fn give_consent_for_user(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: &User,
        scope: &Scope,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let (tokens, ids): (Vec<String>, Vec<Uuid>) = scope
            .iter()
            .map(|token| {
                (
                    token.to_string(),
                    Uuid::from(Ulid::from_datetime_with_source(now.into(), rng)),
                )
            })
            .unzip();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_consents
                    (oauth2_consent_id, user_id, oauth2_client_id, scope_token, created_at)
                SELECT id, $2, $3, scope_token, $5 FROM UNNEST($1::uuid[], $4::text[]) u(id, scope_token)
                ON CONFLICT (user_id, oauth2_client_id, scope_token) DO UPDATE SET refreshed_at = $5
            "#,
            &ids,
            Uuid::from(user.id),
            Uuid::from(client.id),
            &tokens,
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.oauth2_client.delete_by_id",
        skip_all,
        fields(
            db.statement,
            client.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        // Delete the authorization grants
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.authorization_grants",
                db.statement = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_authorization_grants
                    WHERE oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Delete the user consents
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.consents",
                db.statement = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_consents
                    WHERE oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Delete the OAuth 2 sessions related data
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.access_tokens",
                db.statement = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_access_tokens
                    WHERE oauth2_session_id IN (
                        SELECT oauth2_session_id
                        FROM oauth2_sessions
                        WHERE oauth2_client_id = $1
                    )
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.refresh_tokens",
                db.statement = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_refresh_tokens
                    WHERE oauth2_session_id IN (
                        SELECT oauth2_session_id
                        FROM oauth2_sessions
                        WHERE oauth2_client_id = $1
                    )
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.sessions",
                db.statement = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_sessions
                    WHERE oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Now delete the client itself
        let res = sqlx::query!(
            r#"
                DELETE FROM oauth2_clients
                WHERE oauth2_client_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)
    }
}
