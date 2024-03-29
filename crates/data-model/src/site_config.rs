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
use url::Url;

/// Random site configuration we want accessible in various places.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Time-to-live of access tokens.
    pub access_token_ttl: Duration,

    /// Time-to-live of compatibility access tokens.
    pub compat_token_ttl: Duration,

    /// The server name, e.g. "matrix.org".
    pub server_name: String,

    /// The URL to the privacy policy.
    pub policy_uri: Option<Url>,

    /// The URL to the terms of service.
    pub tos_uri: Option<Url>,

    /// Imprint to show in the footer.
    pub imprint: Option<String>,

    /// Whether password login is enabled.
    pub password_login_enabled: bool,

    /// Whether password registration is enabled.
    pub password_registration_enabled: bool,

    /// Whether users can change their email.
    pub email_change_allowed: bool,

    /// Whether users can change their display name.
    pub displayname_change_allowed: bool,

    /// Whether users can change their password.
    pub password_change_allowed: bool,
}
