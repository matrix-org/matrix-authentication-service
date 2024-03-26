// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

use chrono::Duration;
use mas_templates::{SiteBranding, SiteFeatures};
use url::Url;

/// Random site configuration we don't now where to put yet.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    pub access_token_ttl: Duration,
    pub compat_token_ttl: Duration,
    pub server_name: String,
    pub policy_uri: Option<Url>,
    pub tos_uri: Option<Url>,
    pub imprint: Option<String>,
    pub password_login_enabled: bool,
    pub password_registration_enabled: bool,
}

impl SiteConfig {
    #[must_use]
    pub fn templates_branding(&self) -> SiteBranding {
        let mut branding = SiteBranding::new(self.server_name.clone());

        if let Some(policy_uri) = &self.policy_uri {
            branding = branding.with_policy_uri(policy_uri.as_str());
        }

        if let Some(tos_uri) = &self.tos_uri {
            branding = branding.with_tos_uri(tos_uri.as_str());
        }

        if let Some(imprint) = &self.imprint {
            branding = branding.with_imprint(imprint.as_str());
        }

        branding
    }

    #[must_use]
    pub fn templates_features(&self) -> SiteFeatures {
        SiteFeatures {
            password_registration: self.password_registration_enabled,
            password_login: self.password_login_enabled,
        }
    }
}
