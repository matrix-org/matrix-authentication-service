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

use url::Url;

use crate::traits::Route;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBuilder {
    base: Url,
}

impl UrlBuilder {
    fn url_for<U>(&self, destination: &U) -> Url
    where
        U: Route,
    {
        destination.absolute_url(&self.base)
    }

    pub fn absolute_redirect<U>(&self, destination: &U) -> axum::response::Redirect
    where
        U: Route,
    {
        destination.go_absolute(&self.base)
    }

    /// Create a new [`UrlBuilder`] from a base URL
    #[must_use]
    pub fn new(base: Url) -> Self {
        Self { base }
    }

    /// OIDC issuer
    #[must_use]
    pub fn oidc_issuer(&self) -> Url {
        self.base.clone()
    }

    /// OIDC dicovery document URL
    #[must_use]
    pub fn oidc_discovery(&self) -> Url {
        self.url_for(&crate::endpoints::OidcConfiguration)
    }

    /// OAuth 2.0 authorization endpoint
    #[must_use]
    pub fn oauth_authorization_endpoint(&self) -> Url {
        self.url_for(&crate::endpoints::OAuth2AuthorizationEndpoint)
    }

    /// OAuth 2.0 token endpoint
    #[must_use]
    pub fn oauth_token_endpoint(&self) -> Url {
        self.url_for(&crate::endpoints::OAuth2TokenEndpoint)
    }

    /// OAuth 2.0 introspection endpoint
    #[must_use]
    pub fn oauth_introspection_endpoint(&self) -> Url {
        self.url_for(&crate::endpoints::OAuth2Introspection)
    }

    /// OAuth 2.0 client registration endpoint
    #[must_use]
    pub fn oauth_registration_endpoint(&self) -> Url {
        self.url_for(&crate::endpoints::OAuth2RegistrationEndpoint)
    }

    // OIDC userinfo endpoint
    #[must_use]
    pub fn oidc_userinfo_endpoint(&self) -> Url {
        self.url_for(&crate::endpoints::OidcUserinfo)
    }

    /// JWKS URI
    #[must_use]
    pub fn jwks_uri(&self) -> Url {
        self.url_for(&crate::endpoints::OAuth2Keys)
    }

    /// Email verification URL
    #[must_use]
    pub fn email_verification(&self, code: String) -> Url {
        self.url_for(&crate::endpoints::VerifyEmail(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_email_verification_url() {
        let base = Url::parse("https://example.com/").unwrap();
        let builder = UrlBuilder::new(base);
        assert_eq!(
            builder.email_verification("123456abcdef".into()).as_str(),
            "https://example.com/verify/123456abcdef"
        );
    }
}
