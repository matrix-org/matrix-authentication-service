// Copyright 2024 The Matrix.org Foundation C.I.C.
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

#![allow(clippy::str_to_string)] // ComplexObject macro uses &str.to_string()

use async_graphql::{ComplexObject, Enum, SimpleObject, ID};
use url::Url;

pub const SITE_CONFIG_ID: &str = "site_config";
pub const CAPTCHA_CONFIG_ID: &str = "captcha_config";

#[derive(SimpleObject)]
#[graphql(complex)]
#[allow(clippy::struct_excessive_bools)]
pub struct SiteConfig {
    /// The configuration of CAPTCHA provider.
    captcha_config: Option<CaptchaConfig>,

    /// The server name of the homeserver.
    server_name: String,

    /// The URL to the privacy policy.
    policy_uri: Option<Url>,

    /// The URL to the terms of service.
    tos_uri: Option<Url>,

    /// Imprint to show in the footer.
    imprint: Option<String>,

    /// Whether users can change their email.
    email_change_allowed: bool,

    /// Whether users can change their display name.
    display_name_change_allowed: bool,

    /// Whether passwords are enabled for login.
    password_login_enabled: bool,

    /// Whether passwords are enabled and users can change their own passwords.
    password_change_allowed: bool,

    /// Whether passwords are enabled and users can register using a password.
    password_registration_enabled: bool,

    /// Minimum password complexity, from 0 to 4, in terms of a zxcvbn score.
    /// The exact scorer (including dictionaries and other data tables)
    /// in use is <https://crates.io/crates/zxcvbn>.
    minimum_password_complexity: u8,
}

#[derive(SimpleObject)]
#[graphql(complex)]
pub struct CaptchaConfig {
    /// Which Captcha service is being used
    pub service: CaptchaService,

    /// The site key used by the instance
    pub site_key: String,
}

/// Which Captcha service is being used
#[derive(Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaService {
    RecaptchaV2,
    CloudflareTurnstile,
    HCaptcha,
}

#[ComplexObject]
impl SiteConfig {
    /// The ID of the site configuration.
    pub async fn id(&self) -> ID {
        SITE_CONFIG_ID.into()
    }
}

impl SiteConfig {
    /// Create a new [`SiteConfig`] from the data model
    /// [`mas_data_model:::SiteConfig`].
    pub fn new(data_model: &mas_data_model::SiteConfig) -> Self {
        Self {
            captcha_config: data_model.captcha.as_ref().map(CaptchaConfig::new),
            server_name: data_model.server_name.clone(),
            policy_uri: data_model.policy_uri.clone(),
            tos_uri: data_model.tos_uri.clone(),
            imprint: data_model.imprint.clone(),
            email_change_allowed: data_model.email_change_allowed,
            display_name_change_allowed: data_model.displayname_change_allowed,
            password_login_enabled: data_model.password_login_enabled,
            password_change_allowed: data_model.password_change_allowed,
            password_registration_enabled: data_model.password_registration_enabled,
            minimum_password_complexity: data_model.minimum_password_complexity,
        }
    }
}

#[ComplexObject]
impl CaptchaConfig {
    pub async fn id(&self) -> ID {
        CAPTCHA_CONFIG_ID.into()
    }
}

impl CaptchaConfig {
    /// Create a new [`CaptchaConfig`] from the data model
    /// [`mas_data_model:::CaptchaConfig`].
    pub fn new(data_model: &mas_data_model::CaptchaConfig) -> Self {
        Self {
            service: match data_model.service {
                mas_data_model::CaptchaService::RecaptchaV2 => CaptchaService::RecaptchaV2,
                mas_data_model::CaptchaService::CloudflareTurnstile => {
                    CaptchaService::CloudflareTurnstile
                }
                mas_data_model::CaptchaService::HCaptcha => CaptchaService::HCaptcha,
            },
            site_key: data_model.site_key.clone(),
        }
    }
}
