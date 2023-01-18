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
};

pub trait Repository: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    type UpstreamOAuthLinkRepository<'c>: UpstreamOAuthLinkRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type UpstreamOAuthProviderRepository<'c>: UpstreamOAuthProviderRepository<Error = Self::Error>
        + 'c
    where
        Self: 'c;

    type UpstreamOAuthSessionRepository<'c>: UpstreamOAuthSessionRepository<Error = Self::Error>
        + 'c
    where
        Self: 'c;

    type UserRepository<'c>: UserRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type UserEmailRepository<'c>: UserEmailRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type UserPasswordRepository<'c>: UserPasswordRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type BrowserSessionRepository<'c>: BrowserSessionRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type OAuth2ClientRepository<'c>: OAuth2ClientRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type OAuth2AuthorizationGrantRepository<'c>: OAuth2AuthorizationGrantRepository<Error = Self::Error>
        + 'c
    where
        Self: 'c;

    type OAuth2SessionRepository<'c>: OAuth2SessionRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type OAuth2AccessTokenRepository<'c>: OAuth2AccessTokenRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type OAuth2RefreshTokenRepository<'c>: OAuth2RefreshTokenRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type CompatSessionRepository<'c>: CompatSessionRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type CompatSsoLoginRepository<'c>: CompatSsoLoginRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type CompatAccessTokenRepository<'c>: CompatAccessTokenRepository<Error = Self::Error> + 'c
    where
        Self: 'c;

    type CompatRefreshTokenRepository<'c>: CompatRefreshTokenRepository<Error = Self::Error> + 'c
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
