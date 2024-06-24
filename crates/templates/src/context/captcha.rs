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

use std::sync::Arc;

use minijinja::{
    value::{Enumerator, Object},
    Value,
};
use serde::Serialize;

use crate::TemplateContext;

#[derive(Debug)]
struct CaptchaConfig(mas_data_model::CaptchaConfig);

impl Object for CaptchaConfig {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str() {
            Some("service") => Some(match &self.0.service {
                mas_data_model::CaptchaService::RecaptchaV2 => "recaptcha_v2".into(),
                mas_data_model::CaptchaService::CloudflareTurnstile => {
                    "cloudflare_turnstile".into()
                }
                mas_data_model::CaptchaService::HCaptcha => "hcaptcha".into(),
            }),
            Some("site_key") => Some(self.0.site_key.clone().into()),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&["service", "site_key"])
    }
}

/// Context with an optional CAPTCHA configuration in it
#[derive(Serialize)]
pub struct WithCaptcha<T> {
    captcha: Option<Value>,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithCaptcha<T> {
    #[must_use]
    pub(crate) fn new(captcha: Option<mas_data_model::CaptchaConfig>, inner: T) -> Self {
        Self {
            captcha: captcha.map(|captcha| Value::from_object(CaptchaConfig(captcha))),
            inner,
        }
    }
}

impl<T: TemplateContext> TemplateContext for WithCaptcha<T> {
    fn sample(
        now: chrono::DateTime<chrono::prelude::Utc>,
        rng: &mut impl rand::prelude::Rng,
    ) -> Vec<Self>
    where
        Self: Sized,
    {
        let inner = T::sample(now, rng);
        inner
            .into_iter()
            .map(|inner| Self::new(None, inner))
            .collect()
    }
}
