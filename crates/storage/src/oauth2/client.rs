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

use std::{collections::HashMap, string::ToString};

use mas_data_model::{Client, JwksOrJwksUri};
use mas_iana::{
    jose::JsonWebSignatureAlg,
    oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
};
use mas_jose::jwk::PublicJsonWebKeySet;
use oauth2_types::requests::GrantType;
use rand::Rng;
use sqlx::{PgConnection, PgExecutor};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{Clock, DatabaseError, DatabaseInconsistencyError, LookupResultExt};

// XXX: response_types & contacts
#[derive(Debug)]
pub struct OAuth2ClientLookup {
    oauth2_client_id: Uuid,
    encrypted_client_secret: Option<String>,
    redirect_uris: Vec<String>,
    // response_types: Vec<String>,
    grant_type_authorization_code: bool,
    grant_type_refresh_token: bool,
    // contacts: Vec<String>,
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
            redirect_uris,
            response_types,
            grant_types,
            // contacts: self.contacts,
            contacts: vec![],
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

#[tracing::instrument(skip_all, err)]
pub async fn lookup_clients(
    executor: impl PgExecutor<'_>,
    ids: impl IntoIterator<Item = Ulid> + Send,
) -> Result<HashMap<Ulid, Client>, DatabaseError> {
    let ids: Vec<Uuid> = ids.into_iter().map(Uuid::from).collect();
    let res = sqlx::query_as!(
        OAuth2ClientLookup,
        r#"
            SELECT
                c.oauth2_client_id,
                c.encrypted_client_secret,
                ARRAY(
                    SELECT redirect_uri
                    FROM oauth2_client_redirect_uris r
                    WHERE r.oauth2_client_id = c.oauth2_client_id
                ) AS "redirect_uris!",
                c.grant_type_authorization_code,
                c.grant_type_refresh_token,
                c.client_name,
                c.logo_uri,
                c.client_uri,
                c.policy_uri,
                c.tos_uri,
                c.jwks_uri,
                c.jwks,
                c.id_token_signed_response_alg,
                c.userinfo_signed_response_alg,
                c.token_endpoint_auth_method,
                c.token_endpoint_auth_signing_alg,
                c.initiate_login_uri
            FROM oauth2_clients c

            WHERE c.oauth2_client_id = ANY($1::uuid[])
        "#,
        &ids,
    )
    .fetch_all(executor)
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
    skip_all,
    fields(client.id = %id),
    err,
)]
pub async fn lookup_client(
    executor: impl PgExecutor<'_>,
    id: Ulid,
) -> Result<Option<Client>, DatabaseError> {
    let res = sqlx::query_as!(
        OAuth2ClientLookup,
        r#"
            SELECT
                c.oauth2_client_id,
                c.encrypted_client_secret,
                ARRAY(
                    SELECT redirect_uri
                    FROM oauth2_client_redirect_uris r
                    WHERE r.oauth2_client_id = c.oauth2_client_id
                ) AS "redirect_uris!",
                c.grant_type_authorization_code,
                c.grant_type_refresh_token,
                c.client_name,
                c.logo_uri,
                c.client_uri,
                c.policy_uri,
                c.tos_uri,
                c.jwks_uri,
                c.jwks,
                c.id_token_signed_response_alg,
                c.userinfo_signed_response_alg,
                c.token_endpoint_auth_method,
                c.token_endpoint_auth_signing_alg,
                c.initiate_login_uri
            FROM oauth2_clients c

            WHERE c.oauth2_client_id = $1
        "#,
        Uuid::from(id),
    )
    .fetch_one(executor)
    .await
    .to_option()?;

    let Some(res) = res else { return Ok(None) };

    Ok(Some(res.try_into()?))
}

#[tracing::instrument(
    skip_all,
    fields(client.id = client_id),
    err,
)]
pub async fn lookup_client_by_client_id(
    executor: impl PgExecutor<'_>,
    client_id: &str,
) -> Result<Option<Client>, DatabaseError> {
    let Ok(id) = client_id.parse() else { return Ok(None) };
    lookup_client(executor, id).await
}

#[tracing::instrument(
    skip_all,
    fields(client.id = %client_id, client.name = client_name),
    err,
)]
#[allow(clippy::too_many_arguments)]
pub async fn insert_client(
    conn: &mut PgConnection,
    mut rng: impl Rng + Send,
    clock: &Clock,
    client_id: Ulid,
    redirect_uris: &[Url],
    encrypted_client_secret: Option<&str>,
    grant_types: &[GrantType],
    _contacts: &[String],
    client_name: Option<&str>,
    logo_uri: Option<&Url>,
    client_uri: Option<&Url>,
    policy_uri: Option<&Url>,
    tos_uri: Option<&Url>,
    jwks_uri: Option<&Url>,
    jwks: Option<&PublicJsonWebKeySet>,
    id_token_signed_response_alg: Option<&JsonWebSignatureAlg>,
    userinfo_signed_response_alg: Option<&JsonWebSignatureAlg>,
    token_endpoint_auth_method: Option<&OAuthClientAuthenticationMethod>,
    token_endpoint_auth_signing_alg: Option<&JsonWebSignatureAlg>,
    initiate_login_uri: Option<&Url>,
) -> Result<(), sqlx::Error> {
    let grant_type_authorization_code = grant_types.contains(&GrantType::AuthorizationCode);
    let grant_type_refresh_token = grant_types.contains(&GrantType::RefreshToken);
    let logo_uri = logo_uri.map(Url::as_str);
    let client_uri = client_uri.map(Url::as_str);
    let policy_uri = policy_uri.map(Url::as_str);
    let tos_uri = tos_uri.map(Url::as_str);
    let jwks = jwks.map(serde_json::to_value).transpose().unwrap(); // TODO
    let jwks_uri = jwks_uri.map(Url::as_str);
    let id_token_signed_response_alg = id_token_signed_response_alg.map(ToString::to_string);
    let userinfo_signed_response_alg = userinfo_signed_response_alg.map(ToString::to_string);
    let token_endpoint_auth_method = token_endpoint_auth_method.map(ToString::to_string);
    let token_endpoint_auth_signing_alg = token_endpoint_auth_signing_alg.map(ToString::to_string);
    let initiate_login_uri = initiate_login_uri.map(Url::as_str);

    sqlx::query!(
        r#"
            INSERT INTO oauth2_clients
                (oauth2_client_id,
                 encrypted_client_secret,
                 grant_type_authorization_code,
                 grant_type_refresh_token,
                 client_name,
                 logo_uri,
                 client_uri,
                 policy_uri,
                 tos_uri,
                 jwks_uri,
                 jwks,
                 id_token_signed_response_alg,
                 userinfo_signed_response_alg,
                 token_endpoint_auth_method,
                 token_endpoint_auth_signing_alg,
                 initiate_login_uri)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        "#,
        Uuid::from(client_id),
        encrypted_client_secret,
        grant_type_authorization_code,
        grant_type_refresh_token,
        client_name,
        logo_uri,
        client_uri,
        policy_uri,
        tos_uri,
        jwks_uri,
        jwks,
        id_token_signed_response_alg,
        userinfo_signed_response_alg,
        token_endpoint_auth_method,
        token_endpoint_auth_signing_alg,
        initiate_login_uri,
    )
    .execute(&mut *conn)
    .await?;

    let now = clock.now();
    let (ids, redirect_uris): (Vec<Uuid>, Vec<String>) = redirect_uris
        .iter()
        .map(|uri| {
            (
                Uuid::from(Ulid::from_datetime_with_source(now.into(), &mut rng)),
                uri.as_str().to_owned(),
            )
        })
        .unzip();

    sqlx::query!(
        r#"
            INSERT INTO oauth2_client_redirect_uris
                (oauth2_client_redirect_uri_id, oauth2_client_id, redirect_uri)
            SELECT id, $2, redirect_uri
            FROM UNNEST($1::uuid[], $3::text[]) r(id, redirect_uri)
        "#,
        &ids,
        Uuid::from(client_id),
        &redirect_uris,
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_client_from_config(
    conn: &mut PgConnection,
    mut rng: impl Rng + Send,
    clock: &Clock,
    client_id: Ulid,
    client_auth_method: OAuthClientAuthenticationMethod,
    encrypted_client_secret: Option<&str>,
    jwks: Option<&PublicJsonWebKeySet>,
    jwks_uri: Option<&Url>,
    redirect_uris: &[Url],
) -> Result<(), DatabaseError> {
    let jwks = jwks
        .map(serde_json::to_value)
        .transpose()
        .map_err(DatabaseError::to_invalid_operation)?;

    let jwks_uri = jwks_uri.map(Url::as_str);

    let client_auth_method = client_auth_method.to_string();

    sqlx::query!(
        r#"
            INSERT INTO oauth2_clients
                ( oauth2_client_id
                , encrypted_client_secret
                , grant_type_authorization_code
                , grant_type_refresh_token
                , token_endpoint_auth_method
                , jwks
                , jwks_uri
                )
            VALUES
                ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (oauth2_client_id)
            DO
                UPDATE SET encrypted_client_secret = EXCLUDED.encrypted_client_secret
                         , grant_type_authorization_code = EXCLUDED.grant_type_authorization_code
                         , grant_type_refresh_token = EXCLUDED.grant_type_refresh_token
                         , token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method
                         , jwks = EXCLUDED.jwks
                         , jwks_uri = EXCLUDED.jwks_uri
        "#,
        Uuid::from(client_id),
        encrypted_client_secret,
        true,
        true,
        client_auth_method,
        jwks,
        jwks_uri,
    )
    .execute(&mut *conn)
    .await?;

    let now = clock.now();
    let (ids, redirect_uris): (Vec<Uuid>, Vec<String>) = redirect_uris
        .iter()
        .map(|uri| {
            (
                Uuid::from(Ulid::from_datetime_with_source(now.into(), &mut rng)),
                uri.as_str().to_owned(),
            )
        })
        .unzip();

    sqlx::query!(
        r#"
            INSERT INTO oauth2_client_redirect_uris
                (oauth2_client_redirect_uri_id, oauth2_client_id, redirect_uri)
            SELECT id, $2, redirect_uri
            FROM UNNEST($1::uuid[], $3::text[]) r(id, redirect_uri)
        "#,
        &ids,
        Uuid::from(client_id),
        &redirect_uris,
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}
