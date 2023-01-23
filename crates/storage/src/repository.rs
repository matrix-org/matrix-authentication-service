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
use thiserror::Error;

use crate::{
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
    MapErr,
};

pub trait Repository: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    fn map_err<Mapper>(self, mapper: Mapper) -> MapErr<Self, Mapper>
    where
        Self: Sized,
    {
        MapErr::new(self, mapper)
    }

    fn boxed(self) -> BoxRepository<Self::Error>
    where
        Self: Sized + Sync + 'static,
    {
        Box::new(self)
    }

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;
    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c>;

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c>;

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c>;

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c>;

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c>;

    fn user_password<'c>(&'c mut self)
        -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c>;

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c>;

    fn oauth2_client<'c>(&'c mut self)
        -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c>;

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c>;

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c>;

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c>;

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c>;

    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c>;

    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c>;

    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c>;

    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c>;
}

/// An opaque, type-erased error
#[derive(Debug, Error)]
#[error(transparent)]
pub struct RepositoryError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl RepositoryError {
    pub fn from_error<E>(value: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(value),
        }
    }
}

pub type BoxRepository<E = RepositoryError> =
    Box<dyn Repository<Error = E> + Send + Sync + 'static>;

impl<R, F, E> Repository for crate::MapErr<R, F>
where
    R: Repository,
    R::Error: 'static,
    F: FnMut(R::Error) -> E + Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Error = E;

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::new(self.inner).save().map_err(self.mapper).boxed()
    }

    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::new(self.inner).cancel().map_err(self.mapper).boxed()
    }

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.upstream_oauth_link(),
            &mut self.mapper,
        ))
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.upstream_oauth_provider(),
            &mut self.mapper,
        ))
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.upstream_oauth_session(),
            &mut self.mapper,
        ))
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.user(), &mut self.mapper))
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.user_email(), &mut self.mapper))
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.user_password(), &mut self.mapper))
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.browser_session(), &mut self.mapper))
    }

    fn oauth2_client<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.oauth2_client(), &mut self.mapper))
    }

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.oauth2_authorization_grant(),
            &mut self.mapper,
        ))
    }

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.oauth2_session(), &mut self.mapper))
    }

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.oauth2_access_token(),
            &mut self.mapper,
        ))
    }

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.oauth2_refresh_token(),
            &mut self.mapper,
        ))
    }

    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.compat_session(), &mut self.mapper))
    }

    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(self.inner.compat_sso_login(), &mut self.mapper))
    }

    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.compat_access_token(),
            &mut self.mapper,
        ))
    }

    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(MapErr::new(
            self.inner.compat_refresh_token(),
            &mut self.mapper,
        ))
    }
}

impl<R: Repository + ?Sized> Repository for Box<R> {
    type Error = R::Error;

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>
    where
        Self: Sized,
    {
        // This shouldn't be callable?
        unimplemented!()
    }

    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>
    where
        Self: Sized,
    {
        // This shouldn't be callable?
        unimplemented!()
    }

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        (**self).upstream_oauth_link()
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        (**self).upstream_oauth_provider()
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        (**self).upstream_oauth_session()
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        (**self).user()
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        (**self).user_email()
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        (**self).user_password()
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        (**self).browser_session()
    }

    fn oauth2_client<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
        (**self).oauth2_client()
    }

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
        (**self).oauth2_authorization_grant()
    }

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
        (**self).oauth2_session()
    }

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
        (**self).oauth2_access_token()
    }

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
        (**self).oauth2_refresh_token()
    }

    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
        (**self).compat_session()
    }

    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
        (**self).compat_sso_login()
    }

    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
        (**self).compat_access_token()
    }

    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
        (**self).compat_refresh_token()
    }
}
