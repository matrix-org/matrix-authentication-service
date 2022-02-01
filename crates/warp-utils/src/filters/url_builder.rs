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

//! Utility to build URLs

// TODO: move this somewhere else

use std::convert::Infallible;

use mas_config::HttpConfig;
use url::Url;
use warp::Filter;

impl From<&HttpConfig> for UrlBuilder {
    fn from(config: &HttpConfig) -> Self {
        let base = config.public_base.clone();
        Self { base }
    }
}

/// Helps building absolute URLs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBuilder {
    base: Url,
}

impl UrlBuilder {
    /// OIDC issuer
    #[must_use]
    pub fn oidc_issuer(&self) -> Url {
        self.base.clone()
    }

    /// OIDC dicovery document URL
    #[must_use]
    pub fn oidc_discovery(&self) -> Url {
        self.base
            .join(".well-known/openid-configuration")
            .expect("build URL")
    }

    /// OAuth 2.0 authorization endpoint
    #[must_use]
    pub fn oauth_authorization_endpoint(&self) -> Url {
        self.base.join("oauth2/authorize").expect("build URL")
    }

    /// OAuth 2.0 token endpoint
    #[must_use]
    pub fn oauth_token_endpoint(&self) -> Url {
        self.base.join("oauth2/token").expect("build URL")
    }

    /// OAuth 2.0 introspection endpoint
    #[must_use]
    pub fn oauth_introspection_endpoint(&self) -> Url {
        self.base.join("oauth2/introspect").expect("build URL")
    }

    /// OAuth 2.0 introspection endpoint
    #[must_use]
    pub fn oidc_userinfo_endpoint(&self) -> Url {
        self.base.join("oauth2/userinfo").expect("build URL")
    }

    /// JWKS URI
    #[must_use]
    pub fn jwks_uri(&self) -> Url {
        self.base.join("oauth2/keys.json").expect("build URL")
    }

    /// Email verification URL
    #[must_use]
    pub fn email_verification(&self, code: &str) -> Url {
        self.base
            .join("verify")
            .expect("build URL")
            .join(code)
            .expect("build URL")
    }
}

/// Injects an [`UrlBuilder`] to help building absolute URLs
#[must_use]
pub fn url_builder(
    config: &HttpConfig,
) -> impl Filter<Extract = (UrlBuilder,), Error = Infallible> + Clone + Send + Sync + 'static {
    let builder: UrlBuilder = config.into();
    warp::any().map(move || builder.clone())
}
