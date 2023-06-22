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
use clap::{Parser, ValueEnum};
use mas_config::{DatabaseConfig, PasswordsConfig, RootConfig};
use mas_data_model::{Device, TokenType, UpstreamOAuthProviderClaimsImports};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_router::UrlBuilder;
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    oauth2::OAuth2ClientRepository,
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
    Repository, RepositoryAccess, SystemClock,
};
use mas_storage_pg::PgRepository;
use oauth2_types::scope::Scope;
use rand::SeedableRng;
use tracing::{info, info_span, warn};

use crate::util::{database_from_config, password_manager_from_config};

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
    /// Mark email address as verified
    VerifyEmail { username: String, email: String },

    /// Import clients from config
    ImportClients {
        /// Update existing clients
        #[arg(long)]
        update: bool,
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

    /// Issue a compatibility token
    IssueCompatibilityToken {
        /// User for which to issue the token
        username: String,

        /// Device ID to set in the token. If not specified, a random device ID
        /// will be generated.
        device_id: Option<String>,

        /// Whether that token should be admin
        #[arg(long = "yes-i-want-to-grant-synapse-admin-privileges")]
        admin: bool,
    },
}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        let clock = SystemClock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match &self.subcommand {
            SC::SetPassword { username, password } => {
                let _span =
                    info_span!("cli.manage.set_password", user.username = %username).entered();

                let database_config: DatabaseConfig = root.load_config()?;
                let passwords_config: PasswordsConfig = root.load_config()?;

                let pool = database_from_config(&database_config).await?;
                let password_manager = password_manager_from_config(&passwords_config).await?;

                let mut repo = PgRepository::from_pool(&pool).await?.boxed();
                let user = repo
                    .user()
                    .find_by_username(username)
                    .await?
                    .context("User not found")?;

                let password = password.as_bytes().to_vec().into();

                let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;

                repo.user_password()
                    .add(&mut rng, &clock, &user, version, hashed_password, None)
                    .await?;

                info!(%user.id, %user.username, "Password changed");
                repo.save().await?;

                Ok(())
            }

            SC::VerifyEmail { username, email } => {
                let _span = info_span!(
                    "cli.manage.verify_email",
                    user.username = username,
                    user_email.email = email
                )
                .entered();

                let config: DatabaseConfig = root.load_config()?;
                let pool = database_from_config(&config).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                let user = repo
                    .user()
                    .find_by_username(username)
                    .await?
                    .context("User not found")?;

                let email = repo
                    .user_email()
                    .find(&user, email)
                    .await?
                    .context("Email not found")?;
                let email = repo.user_email().mark_as_verified(&clock, email).await?;

                repo.save().await?;
                info!(?email, "Email marked as verified");

                Ok(())
            }

            SC::ImportClients { update } => {
                let _span = info_span!("cli.manage.import_clients").entered();

                let config: RootConfig = root.load_config()?;
                let pool = database_from_config(&config.database).await?;
                let encrypter = config.secrets.encrypter();

                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                for client in config.clients.iter() {
                    let client_id = client.client_id;

                    let existing = repo.oauth2_client().lookup(client_id).await?.is_some();
                    if !update && existing {
                        warn!(%client_id, "Skipping already imported client. Run with --update to update existing clients.");
                        continue;
                    }

                    if existing {
                        info!(%client_id, "Updating client");
                    } else {
                        info!(%client_id, "Importing client");
                    }

                    let client_secret = client.client_secret();
                    let client_auth_method = client.client_auth_method();
                    let jwks = client.jwks();
                    let jwks_uri = client.jwks_uri();

                    // TODO: should be moved somewhere else
                    let encrypted_client_secret = client_secret
                        .map(|client_secret| encrypter.encryt_to_string(client_secret.as_bytes()))
                        .transpose()?;

                    repo.oauth2_client()
                        .add_from_config(
                            &mut rng,
                            &clock,
                            client_id,
                            client_auth_method,
                            encrypted_client_secret,
                            jwks.cloned(),
                            jwks_uri.cloned(),
                            client.redirect_uris.clone(),
                        )
                        .await?;
                }

                repo.save().await?;

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
                let _span = info_span!(
                    "cli.manage.add_oauth_upstream",
                    upstream_oauth_provider.issuer = issuer,
                    upstream_oauth_provider.client_id = client_id,
                )
                .entered();

                let config: RootConfig = root.load_config()?;
                let encrypter = config.secrets.encrypter();
                let pool = database_from_config(&config.database).await?;
                let url_builder = UrlBuilder::new(config.http.public_base);
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

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

                let provider = repo
                    .upstream_oauth_provider()
                    .add(
                        &mut rng,
                        &clock,
                        issuer.clone(),
                        scope.clone(),
                        token_endpoint_auth_method,
                        token_endpoint_signing_alg,
                        client_id.clone(),
                        encrypted_client_secret,
                        UpstreamOAuthProviderClaimsImports::default(),
                    )
                    .await?;

                repo.save().await?;

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

            SC::IssueCompatibilityToken {
                username,
                admin,
                device_id,
            } => {
                let config: DatabaseConfig = root.load_config()?;
                let pool = database_from_config(&config).await?;
                let mut repo = PgRepository::from_pool(&pool).await?.boxed();

                let user = repo
                    .user()
                    .find_by_username(username)
                    .await?
                    .context("User not found")?;

                let device = if let Some(device_id) = device_id {
                    device_id.clone().try_into()?
                } else {
                    Device::generate(&mut rng)
                };

                let compat_session = repo
                    .compat_session()
                    .add(&mut rng, &clock, &user, device, *admin)
                    .await?;

                let token = TokenType::CompatAccessToken.generate(&mut rng);

                let compat_access_token = repo
                    .compat_access_token()
                    .add(&mut rng, &clock, &compat_session, token, None)
                    .await?;

                repo.save().await?;

                info!(
                    %compat_access_token.id,
                    %compat_session.id,
                    %compat_session.device,
                    %user.id,
                    %user.username,
                    "Compatibility token issued: {}", compat_access_token.token
                );

                Ok(())
            }
        }
    }
}
