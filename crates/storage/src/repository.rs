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

use sqlx::{PgConnection, Postgres, Transaction};

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
};

pub trait Repository {
    type UpstreamOAuthLinkRepository<'c>
    where
        Self: 'c;

    type UpstreamOAuthProviderRepository<'c>
    where
        Self: 'c;

    type UpstreamOAuthSessionRepository<'c>
    where
        Self: 'c;

    type UserRepository<'c>
    where
        Self: 'c;

    type UserEmailRepository<'c>
    where
        Self: 'c;

    type UserPasswordRepository<'c>
    where
        Self: 'c;

    type BrowserSessionRepository<'c>
    where
        Self: 'c;

    type OAuth2ClientRepository<'c>
    where
        Self: 'c;

    type OAuth2AuthorizationGrantRepository<'c>
    where
        Self: 'c;

    type OAuth2SessionRepository<'c>
    where
        Self: 'c;

    type OAuth2AccessTokenRepository<'c>
    where
        Self: 'c;

    type OAuth2RefreshTokenRepository<'c>
    where
        Self: 'c;

    type CompatSessionRepository<'c>
    where
        Self: 'c;

    type CompatSsoLoginRepository<'c>
    where
        Self: 'c;

    type CompatAccessTokenRepository<'c>
    where
        Self: 'c;

    type CompatRefreshTokenRepository<'c>
    where
        Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_>;
    fn upstream_oauth_provider(&mut self) -> Self::UpstreamOAuthProviderRepository<'_>;
    fn upstream_oauth_session(&mut self) -> Self::UpstreamOAuthSessionRepository<'_>;
    fn user(&mut self) -> Self::UserRepository<'_>;
    fn user_email(&mut self) -> Self::UserEmailRepository<'_>;
    fn user_password(&mut self) -> Self::UserPasswordRepository<'_>;
    fn browser_session(&mut self) -> Self::BrowserSessionRepository<'_>;
    fn oauth2_client(&mut self) -> Self::OAuth2ClientRepository<'_>;
    fn oauth2_authorization_grant(&mut self) -> Self::OAuth2AuthorizationGrantRepository<'_>;
    fn oauth2_session(&mut self) -> Self::OAuth2SessionRepository<'_>;
    fn oauth2_access_token(&mut self) -> Self::OAuth2AccessTokenRepository<'_>;
    fn oauth2_refresh_token(&mut self) -> Self::OAuth2RefreshTokenRepository<'_>;
    fn compat_session(&mut self) -> Self::CompatSessionRepository<'_>;
    fn compat_sso_login(&mut self) -> Self::CompatSsoLoginRepository<'_>;
    fn compat_access_token(&mut self) -> Self::CompatAccessTokenRepository<'_>;
    fn compat_refresh_token(&mut self) -> Self::CompatRefreshTokenRepository<'_>;
}

impl Repository for PgConnection {
    type UpstreamOAuthLinkRepository<'c> = PgUpstreamOAuthLinkRepository<'c> where Self: 'c;
    type UpstreamOAuthProviderRepository<'c> = PgUpstreamOAuthProviderRepository<'c> where Self: 'c;
    type UpstreamOAuthSessionRepository<'c> = PgUpstreamOAuthSessionRepository<'c> where Self: 'c;
    type UserRepository<'c> = PgUserRepository<'c> where Self: 'c;
    type UserEmailRepository<'c> = PgUserEmailRepository<'c> where Self: 'c;
    type UserPasswordRepository<'c> = PgUserPasswordRepository<'c> where Self: 'c;
    type BrowserSessionRepository<'c> = PgBrowserSessionRepository<'c> where Self: 'c;
    type OAuth2ClientRepository<'c> = PgOAuth2ClientRepository<'c> where Self: 'c;
    type OAuth2AuthorizationGrantRepository<'c> = PgOAuth2AuthorizationGrantRepository<'c> where Self: 'c;
    type OAuth2SessionRepository<'c> = PgOAuth2SessionRepository<'c> where Self: 'c;
    type OAuth2AccessTokenRepository<'c> = PgOAuth2AccessTokenRepository<'c> where Self: 'c;
    type OAuth2RefreshTokenRepository<'c> = PgOAuth2RefreshTokenRepository<'c> where Self: 'c;
    type CompatSessionRepository<'c> = PgCompatSessionRepository<'c> where Self: 'c;
    type CompatSsoLoginRepository<'c> = PgCompatSsoLoginRepository<'c> where Self: 'c;
    type CompatAccessTokenRepository<'c> = PgCompatAccessTokenRepository<'c> where Self: 'c;
    type CompatRefreshTokenRepository<'c> = PgCompatRefreshTokenRepository<'c> where Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_> {
        PgUpstreamOAuthLinkRepository::new(self)
    }

    fn upstream_oauth_provider(&mut self) -> Self::UpstreamOAuthProviderRepository<'_> {
        PgUpstreamOAuthProviderRepository::new(self)
    }

    fn upstream_oauth_session(&mut self) -> Self::UpstreamOAuthSessionRepository<'_> {
        PgUpstreamOAuthSessionRepository::new(self)
    }

    fn user(&mut self) -> Self::UserRepository<'_> {
        PgUserRepository::new(self)
    }

    fn user_email(&mut self) -> Self::UserEmailRepository<'_> {
        PgUserEmailRepository::new(self)
    }

    fn user_password(&mut self) -> Self::UserPasswordRepository<'_> {
        PgUserPasswordRepository::new(self)
    }

    fn browser_session(&mut self) -> Self::BrowserSessionRepository<'_> {
        PgBrowserSessionRepository::new(self)
    }

    fn oauth2_client(&mut self) -> Self::OAuth2ClientRepository<'_> {
        PgOAuth2ClientRepository::new(self)
    }

    fn oauth2_authorization_grant(&mut self) -> Self::OAuth2AuthorizationGrantRepository<'_> {
        PgOAuth2AuthorizationGrantRepository::new(self)
    }

    fn oauth2_session(&mut self) -> Self::OAuth2SessionRepository<'_> {
        PgOAuth2SessionRepository::new(self)
    }

    fn oauth2_access_token(&mut self) -> Self::OAuth2AccessTokenRepository<'_> {
        PgOAuth2AccessTokenRepository::new(self)
    }

    fn oauth2_refresh_token(&mut self) -> Self::OAuth2RefreshTokenRepository<'_> {
        PgOAuth2RefreshTokenRepository::new(self)
    }

    fn compat_session(&mut self) -> Self::CompatSessionRepository<'_> {
        PgCompatSessionRepository::new(self)
    }

    fn compat_sso_login(&mut self) -> Self::CompatSsoLoginRepository<'_> {
        PgCompatSsoLoginRepository::new(self)
    }

    fn compat_access_token(&mut self) -> Self::CompatAccessTokenRepository<'_> {
        PgCompatAccessTokenRepository::new(self)
    }

    fn compat_refresh_token(&mut self) -> Self::CompatRefreshTokenRepository<'_> {
        PgCompatRefreshTokenRepository::new(self)
    }
}

impl<'t> Repository for Transaction<'t, Postgres> {
    type UpstreamOAuthLinkRepository<'c> = PgUpstreamOAuthLinkRepository<'c> where Self: 'c;
    type UpstreamOAuthProviderRepository<'c> = PgUpstreamOAuthProviderRepository<'c> where Self: 'c;
    type UpstreamOAuthSessionRepository<'c> = PgUpstreamOAuthSessionRepository<'c> where Self: 'c;
    type UserRepository<'c> = PgUserRepository<'c> where Self: 'c;
    type UserEmailRepository<'c> = PgUserEmailRepository<'c> where Self: 'c;
    type UserPasswordRepository<'c> = PgUserPasswordRepository<'c> where Self: 'c;
    type BrowserSessionRepository<'c> = PgBrowserSessionRepository<'c> where Self: 'c;
    type OAuth2ClientRepository<'c> = PgOAuth2ClientRepository<'c> where Self: 'c;
    type OAuth2AuthorizationGrantRepository<'c> = PgOAuth2AuthorizationGrantRepository<'c> where Self: 'c;
    type OAuth2SessionRepository<'c> = PgOAuth2SessionRepository<'c> where Self: 'c;
    type OAuth2AccessTokenRepository<'c> = PgOAuth2AccessTokenRepository<'c> where Self: 'c;
    type OAuth2RefreshTokenRepository<'c> = PgOAuth2RefreshTokenRepository<'c> where Self: 'c;
    type CompatSessionRepository<'c> = PgCompatSessionRepository<'c> where Self: 'c;
    type CompatSsoLoginRepository<'c> = PgCompatSsoLoginRepository<'c> where Self: 'c;
    type CompatAccessTokenRepository<'c> = PgCompatAccessTokenRepository<'c> where Self: 'c;
    type CompatRefreshTokenRepository<'c> = PgCompatRefreshTokenRepository<'c> where Self: 'c;

    fn upstream_oauth_link(&mut self) -> Self::UpstreamOAuthLinkRepository<'_> {
        PgUpstreamOAuthLinkRepository::new(self)
    }

    fn upstream_oauth_provider(&mut self) -> Self::UpstreamOAuthProviderRepository<'_> {
        PgUpstreamOAuthProviderRepository::new(self)
    }

    fn upstream_oauth_session(&mut self) -> Self::UpstreamOAuthSessionRepository<'_> {
        PgUpstreamOAuthSessionRepository::new(self)
    }

    fn user(&mut self) -> Self::UserRepository<'_> {
        PgUserRepository::new(self)
    }

    fn user_email(&mut self) -> Self::UserEmailRepository<'_> {
        PgUserEmailRepository::new(self)
    }

    fn user_password(&mut self) -> Self::UserPasswordRepository<'_> {
        PgUserPasswordRepository::new(self)
    }

    fn browser_session(&mut self) -> Self::BrowserSessionRepository<'_> {
        PgBrowserSessionRepository::new(self)
    }

    fn oauth2_client(&mut self) -> Self::OAuth2ClientRepository<'_> {
        PgOAuth2ClientRepository::new(self)
    }

    fn oauth2_authorization_grant(&mut self) -> Self::OAuth2AuthorizationGrantRepository<'_> {
        PgOAuth2AuthorizationGrantRepository::new(self)
    }

    fn oauth2_session(&mut self) -> Self::OAuth2SessionRepository<'_> {
        PgOAuth2SessionRepository::new(self)
    }

    fn oauth2_access_token(&mut self) -> Self::OAuth2AccessTokenRepository<'_> {
        PgOAuth2AccessTokenRepository::new(self)
    }

    fn oauth2_refresh_token(&mut self) -> Self::OAuth2RefreshTokenRepository<'_> {
        PgOAuth2RefreshTokenRepository::new(self)
    }

    fn compat_session(&mut self) -> Self::CompatSessionRepository<'_> {
        PgCompatSessionRepository::new(self)
    }

    fn compat_sso_login(&mut self) -> Self::CompatSsoLoginRepository<'_> {
        PgCompatSsoLoginRepository::new(self)
    }

    fn compat_access_token(&mut self) -> Self::CompatAccessTokenRepository<'_> {
        PgCompatAccessTokenRepository::new(self)
    }

    fn compat_refresh_token(&mut self) -> Self::CompatRefreshTokenRepository<'_> {
        PgCompatRefreshTokenRepository::new(self)
    }
}
