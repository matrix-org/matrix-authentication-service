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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::ConfigurationSection;

fn default_token_ttl() -> Duration {
    Duration::microseconds(5 * 60 * 1000 * 1000)
}

fn is_default_token_ttl(value: &Duration) -> bool {
    *value == default_token_ttl()
}

const fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_true(value: &bool) -> bool {
    *value == default_true()
}

const fn default_false() -> bool {
    false
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_false(value: &bool) -> bool {
    *value == default_false()
}

/// Configuration sections for experimental options
///
/// Do not change these options unless you know what you are doing.
#[serde_as]
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExperimentalConfig {
    /// Time-to-live of access tokens in seconds. Defaults to 5 minutes.
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_token_ttl",
        skip_serializing_if = "is_default_token_ttl"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub access_token_ttl: Duration,

    /// Time-to-live of compatibility access tokens in seconds. Defaults to 5
    /// minutes.
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_token_ttl",
        skip_serializing_if = "is_default_token_ttl"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub compat_token_ttl: Duration,

    /// Whether to enable self-service password registration. Defaults to `true`
    /// if password authentication is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub password_registration_enabled: bool,

    /// Whether users are allowed to change their email addresses. Defaults to
    /// `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub email_change_allowed: bool,

    /// Whether users are allowed to change their display names. Defaults to
    /// `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub displayname_change_allowed: bool,

    /// Whether users are allowed to change their passwords. Defaults to `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub password_change_allowed: bool,

    /// Whether email-based account recovery is enabled. Defaults to `false`.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub account_recovery_enabled: bool,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: default_token_ttl(),
            compat_token_ttl: default_token_ttl(),
            password_registration_enabled: default_true(),
            email_change_allowed: default_true(),
            displayname_change_allowed: default_true(),
            password_change_allowed: default_true(),
            account_recovery_enabled: default_false(),
        }
    }
}

impl ExperimentalConfig {
    pub(crate) fn is_default(&self) -> bool {
        is_default_token_ttl(&self.access_token_ttl)
            && is_default_token_ttl(&self.compat_token_ttl)
            && is_default_true(&self.password_registration_enabled)
            && is_default_true(&self.email_change_allowed)
            && is_default_true(&self.displayname_change_allowed)
            && is_default_true(&self.password_change_allowed)
            && is_default_false(&self.account_recovery_enabled)
    }
}

impl ConfigurationSection for ExperimentalConfig {
    const PATH: Option<&'static str> = Some("experimental");
}
