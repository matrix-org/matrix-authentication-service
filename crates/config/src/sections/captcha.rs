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

use schemars::JsonSchema;
use serde::{de::Error, Deserialize, Serialize};

use crate::ConfigurationSection;

/// Which service should be used for CAPTCHA protection
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
pub enum CaptchaServiceKind {
    /// Use Google's reCAPTCHA v2 API
    #[serde(rename = "recaptcha_v2")]
    RecaptchaV2,

    /// Use Cloudflare Turnstile
    #[serde(rename = "cloudflare_turnstile")]
    CloudflareTurnstile,

    /// Use ``HCaptcha``
    #[serde(rename = "hcaptcha")]
    HCaptcha,
}

/// Configuration section to setup CAPTCHA protection on a few operations
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize, Default)]
pub struct CaptchaConfig {
    /// Which service should be used for CAPTCHA protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<CaptchaServiceKind>,

    /// The site key to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,

    /// The secret key to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

impl CaptchaConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        self.service.is_none() && self.site_key.is_none() && self.secret_key.is_none()
    }
}

impl ConfigurationSection for CaptchaConfig {
    const PATH: Option<&'static str> = Some("captcha");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), field.to_owned()];
            error
        };

        let missing_field = |field: &'static str| {
            error_on_field(figment::error::Error::missing_field(field), field)
        };

        if let Some(CaptchaServiceKind::RecaptchaV2) = self.service {
            if self.site_key.is_none() {
                return Err(missing_field("site_key"));
            }

            if self.secret_key.is_none() {
                return Err(missing_field("secret_key"));
            }
        }

        Ok(())
    }
}
