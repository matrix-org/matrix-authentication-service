// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use async_trait::async_trait;
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ConfigurationSection;

/// Configuration section for tweaking the branding of the service
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize, Default)]
pub struct BrandingConfig {
    /// A human-readable name. Defaults to the server's address.
    pub service_name: Option<String>,

    /// Link to a privacy policy, displayed in the footer of web pages and
    /// emails. It is also advertised to clients through the `op_policy_uri`
    /// OIDC provider metadata.
    pub policy_uri: Option<Url>,

    /// Link to a terms of service document, displayed in the footer of web
    /// pages and emails. It is also advertised to clients through the
    /// `op_tos_uri` OIDC provider metadata.
    pub tos_uri: Option<Url>,

    /// Legal imprint, displayed in the footer in the footer of web pages and
    /// emails.
    pub imprint: Option<String>,

    /// Logo displayed in some web pages.
    pub logo_uri: Option<Url>,
}

#[async_trait]
impl ConfigurationSection for BrandingConfig {
    const PATH: Option<&'static str> = Some("branding");

    async fn generate<R>(_rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
