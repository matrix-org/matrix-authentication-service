// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use anyhow::Context;
use argon2::Argon2;
use clap::{Parser, ValueEnum};
use mas_config::{DatabaseConfig, RootConfig};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_router::UrlBuilder;
use mas_storage::{
    oauth2::client::{insert_client_from_config, lookup_client, truncate_clients},
    user::{
        lookup_user_by_username, lookup_user_email, mark_user_email_as_verified, register_user,
        set_password,
    },
    Clock, LookupError,
};
use oauth2_types::scope::Scope;
use rand::SeedableRng;
use tracing::{info, warn};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum AuthenticationMethod {
    /// Client doesn't use any authentication
    None,

    /// Client sends its `client_secret` in the request body
    ClientSecretPost,

    /// Client sends its `client_secret` in the authorization header
    ClientSecretBasic,

    /// Client uses its `client_secret` to sign a client assertion JWT
    ClientSecretJwt,

    /// Client uses its private keys to sign a client assertion JWT
    PrivateKeyJwt,
}

impl AuthenticationMethod {
    fn requires_client_secret(self) -> bool {
        matches!(
            self,
            Self::ClientSecretJwt | Self::ClientSecretPost | Self::ClientSecretBasic
        )
    }
}

impl From<AuthenticationMethod> for OAuthClientAuthenticationMethod {
    fn from(val: AuthenticationMethod) -> Self {
        (&val).into()
    }
}

impl From<&AuthenticationMethod> for OAuthClientAuthenticationMethod {
    fn from(val: &AuthenticationMethod) -> Self {
        match val {
            AuthenticationMethod::None => OAuthClientAuthenticationMethod::None,
            AuthenticationMethod::ClientSecretPost => {
                OAuthClientAuthenticationMethod::ClientSecretPost
            }
            AuthenticationMethod::ClientSecretBasic => {
                OAuthClientAuthenticationMethod::ClientSecretBasic
            }
            AuthenticationMethod::ClientSecretJwt => {
                OAuthClientAuthenticationMethod::ClientSecretJwt
            }
            AuthenticationMethod::PrivateKeyJwt => OAuthClientAuthenticationMethod::PrivateKeyJwt,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SigningAlgorithm {
    #[value(name = "HS256")]
    HS256,
    #[value(name = "HS384")]
    HS384,
    #[value(name = "HS512")]
    HS512,
    #[value(name = "RS256")]
    RS256,
    #[value(name = "RS384")]
    RS384,
    #[value(name = "RS512")]
    RS512,
    #[value(name = "PS256")]
    PS256,
    #[value(name = "PS384")]
    PS384,
    #[value(name = "PS512")]
    PS512,
    #[value(name = "ES256")]
    ES256,
    #[value(name = "ES384")]
    ES384,
    #[value(name = "ES256K")]
    ES256K,
}

impl From<SigningAlgorithm> for JsonWebSignatureAlg {
    fn from(val: SigningAlgorithm) -> Self {
        (&val).into()
    }
}

impl From<&SigningAlgorithm> for JsonWebSignatureAlg {
    fn from(val: &SigningAlgorithm) -> Self {
        match val {
            SigningAlgorithm::HS256 => Self::Hs256,
            SigningAlgorithm::HS384 => Self::Hs384,
            SigningAlgorithm::HS512 => Self::Hs512,
            SigningAlgorithm::RS256 => Self::Rs256,
            SigningAlgorithm::RS384 => Self::Rs384,
            SigningAlgorithm::RS512 => Self::Rs512,
            SigningAlgorithm::PS256 => Self::Ps256,
            SigningAlgorithm::PS384 => Self::Ps384,
            SigningAlgorithm::PS512 => Self::Ps512,
            SigningAlgorithm::ES256 => Self::Es256,
            SigningAlgorithm::ES384 => Self::Es384,
            SigningAlgorithm::ES256K => Self::Es256K,
        }
    }
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Register a new user
    Register { username: String, password: String },

    /// Mark email address as verified
    VerifyEmail { username: String, email: String },

    /// Import clients from config
    ImportClients {
        /// Remove all clients before importing
        #[arg(long)]
        truncate: bool,
    },

    /// Set a user password
    SetPassword { username: String, password: String },

    /// Add an OAuth 2.0 upstream
    #[command(name = "add-oauth-upstream")]
    AddOAuthUpstream {
        /// Issuer URL
        issuer: String,

        /// Scope to ask for when authorizing with this upstream.
        ///
        /// This should include at least the `openid` scope.
        scope: Scope,

        /// Client authentication method used when using the token endpoint.
        #[arg(value_enum)]
        token_endpoint_auth_method: AuthenticationMethod,

        /// Client ID
        client_id: String,

        /// JWT signing algorithm used when authenticating for the token
        /// endpoint.
        #[arg(long, value_enum)]
        signing_alg: Option<SigningAlgorithm>,

        /// Client Secret
        #[arg(long)]
        client_secret: Option<String>,
    },
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        let clock = Clock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match &self.subcommand {
            SC::Register { username, password } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = config.connect().await?;
                let mut txn = pool.begin().await?;
                let hasher = Argon2::default();

                let user =
                    register_user(&mut txn, &mut rng, &clock, hasher, username, password).await?;
                txn.commit().await?;
                info!(%user.id, %user.username, "User registered");

                Ok(())
            }

            SC::SetPassword { username, password } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = config.connect().await?;
                let mut txn = pool.begin().await?;
                let hasher = Argon2::default();
                let user = lookup_user_by_username(&mut txn, username)
                    .await?
                    .context("User not found")?;

                set_password(&mut txn, &mut rng, &clock, hasher, &user, password).await?;
                info!(%user.id, %user.username, "Password changed");
                txn.commit().await?;

                Ok(())
            }

            SC::VerifyEmail { username, email } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = config.connect().await?;
                let mut txn = pool.begin().await?;

                let user = lookup_user_by_username(&mut txn, username)
                    .await?
                    .context("User not found")?;
                let email = lookup_user_email(&mut txn, &user, email)
                    .await?
                    .context("Email not found")?;
                let email = mark_user_email_as_verified(&mut txn, &clock, email).await?;

                txn.commit().await?;
                info!(?email, "Email marked as verified");

                Ok(())
            }

            SC::ImportClients { truncate } => {
                let config: RootConfig = root.load_config()?;
                let pool = config.database.connect().await?;
                let encrypter = config.secrets.encrypter();

                let mut txn = pool.begin().await?;

                if *truncate {
                    warn!("Removing all clients first");
                    truncate_clients(&mut txn).await?;
                }

                for client in config.clients.iter() {
                    let client_id = client.client_id;
                    let res = lookup_client(&mut txn, client_id).await;
                    match res {
                        Ok(_) => {
                            warn!(%client_id, "Skipping already imported client");
                            continue;
                        }
                        Err(e) if e.not_found() => {}
                        Err(e) => anyhow::bail!(e),
                    }

                    info!(%client_id, "Importing client");
                    let client_secret = client.client_secret();
                    let client_auth_method = client.client_auth_method();
                    let jwks = client.jwks();
                    let jwks_uri = client.jwks_uri();
                    let redirect_uris = &client.redirect_uris;

                    // TODO: should be moved somewhere else
                    let encrypted_client_secret = client_secret
                        .map(|client_secret| encrypter.encryt_to_string(client_secret.as_bytes()))
                        .transpose()?;

                    insert_client_from_config(
                        &mut txn,
                        &mut rng,
                        &clock,
                        client_id,
                        client_auth_method,
                        encrypted_client_secret.as_deref(),
                        jwks,
                        jwks_uri,
                        redirect_uris,
                    )
                    .await?;
                }

                txn.commit().await?;

                Ok(())
            }

            SC::AddOAuthUpstream {
                issuer,
                scope,
                token_endpoint_auth_method,
                client_id,
                client_secret,
                signing_alg,
            } => {
                let config: RootConfig = root.load_config()?;
                let encrypter = config.secrets.encrypter();
                let pool = config.database.connect().await?;
                let url_builder = UrlBuilder::new(config.http.public_base);
                let mut conn = pool.acquire().await?;

                let requires_client_secret = token_endpoint_auth_method.requires_client_secret();

                let token_endpoint_auth_method: OAuthClientAuthenticationMethod =
                    token_endpoint_auth_method.into();

                let token_endpoint_signing_alg: Option<JsonWebSignatureAlg> =
                    signing_alg.as_ref().map(Into::into);

                tracing::info!(%issuer, %scope, %token_endpoint_auth_method, %client_id, "Adding OAuth upstream");

                if client_secret.is_none() && requires_client_secret {
                    tracing::warn!("Token endpoint auth method requires a client secret, but none were provided");
                }

                let encrypted_client_secret = client_secret
                    .as_deref()
                    .map(|client_secret| encrypter.encryt_to_string(client_secret.as_bytes()))
                    .transpose()?;

                let provider = mas_storage::upstream_oauth2::add_provider(
                    &mut conn,
                    &mut rng,
                    &clock,
                    issuer.clone(),
                    scope.clone(),
                    token_endpoint_auth_method,
                    token_endpoint_signing_alg,
                    client_id.clone(),
                    encrypted_client_secret,
                )
                .await?;

                let redirect_uri = url_builder.upstream_oauth_callback(provider.id);
                let auth_uri = url_builder.upstream_oauth_authorize(provider.id);
                tracing::info!(
                    %provider.id,
                    %provider.client_id,
                    provider.redirect_uri = %redirect_uri,
                    "Test authorization by going to {auth_uri}"
                );

                Ok(())
            }
        }
    }
}
