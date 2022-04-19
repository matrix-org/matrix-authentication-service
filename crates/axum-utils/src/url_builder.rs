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

/// Helps building absolute URLs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBuilder {
    base: Url,
}

impl UrlBuilder {
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

    /// OAuth 2.0 client registration endpoint
    #[must_use]
    pub fn oauth_registration_endpoint(&self) -> Url {
        self.base.join("oauth2/registration").expect("build URL")
    }

    /// OpenID Connect userinfo endpoint
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
            .join("verify/")
            .expect("build URL")
            .join(code)
            .expect("build URL")
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
            builder.email_verification("123456abcdef").as_str(),
            "https://example.com/verify/123456abcdef"
        );
    }
}
