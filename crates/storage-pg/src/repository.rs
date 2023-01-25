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

use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use mas_storage::{
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
        CompatSsoLoginRepository,
    },
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository, OAuth2ClientRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    user::{BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository},
    Repository, RepositoryAccess, RepositoryTransaction,
};
use sqlx::{PgPool, Postgres, Transaction};

use crate::{
    compat::{
        PgCompatAccessTokenRepository, PgCompatRefreshTokenRepository, PgCompatSessionRepository,
        PgCompatSsoLoginRepository,
    },
    oauth2::{
        PgOAuth2AccessTokenRepository, PgOAuth2AuthorizationGrantRepository,
        PgOAuth2ClientRepository, PgOAuth2RefreshTokenRepository, PgOAuth2SessionRepository,
    },
    upstream_oauth2::{
        PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
        PgUpstreamOAuthSessionRepository,
    },
    user::{
        PgBrowserSessionRepository, PgUserEmailRepository, PgUserPasswordRepository,
        PgUserRepository,
    },
    DatabaseError,
};

/// An implementation of the [`Repository`] trait backed by a PostgreSQL
/// transaction.
pub struct PgRepository {
    txn: Transaction<'static, Postgres>,
}

impl PgRepository {
    /// Create a new [`PgRepository`] from a PostgreSQL connection pool,
    /// starting a transaction.
    ///
    /// # Errors
    ///
    /// Returns a [`DatabaseError`] if the transaction could not be started.
    pub async fn from_pool(pool: &PgPool) -> Result<Self, DatabaseError> {
        let txn = pool.begin().await?;
        Ok(PgRepository { txn })
    }
}

impl Repository<DatabaseError> for PgRepository {}

impl RepositoryTransaction for PgRepository {
    type Error = DatabaseError;

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        self.txn.commit().map_err(DatabaseError::from).boxed()
    }

    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        self.txn.rollback().map_err(DatabaseError::from).boxed()
    }
}

impl RepositoryAccess for PgRepository {
    type Error = DatabaseError;

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthLinkRepository::new(&mut self.txn))
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthProviderRepository::new(&mut self.txn))
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthSessionRepository::new(&mut self.txn))
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRepository::new(&mut self.txn))
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserEmailRepository::new(&mut self.txn))
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPasswordRepository::new(&mut self.txn))
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgBrowserSessionRepository::new(&mut self.txn))
    }

    fn oauth2_client<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2ClientRepository::new(&mut self.txn))
    }

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AuthorizationGrantRepository::new(&mut self.txn))
    }

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2SessionRepository::new(&mut self.txn))
    }

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AccessTokenRepository::new(&mut self.txn))
    }

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2RefreshTokenRepository::new(&mut self.txn))
    }

    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatSessionRepository::new(&mut self.txn))
    }

    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatSsoLoginRepository::new(&mut self.txn))
    }

    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatAccessTokenRepository::new(&mut self.txn))
    }

    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatRefreshTokenRepository::new(&mut self.txn))
    }
}
