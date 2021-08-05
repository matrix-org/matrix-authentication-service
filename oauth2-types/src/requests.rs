// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::{collections::HashSet, hash::Hash};

use chrono::Duration;
use language_tags::LanguageTag;
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{rust::StringWithSeparator, serde_as, DurationSeconds, SpaceSeparator};
use url::Url;

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[display(style = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
    IdToken,
    Token,
    None,
}

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[display(style = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct AuthorizationRequest {
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, ResponseType>")]
    pub response_type: HashSet<ResponseType>,

    pub client_id: String,

    pub redirect_uri: Option<Url>,

    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    pub scope: HashSet<String>,

    pub state: Option<String>,

    pub response_mode: Option<ResponseMode>,

    pub nonce: Option<String>,

    display: Option<Display>,

    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[serde(default)]
    pub max_age: Option<Duration>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    ui_locales: Option<Vec<LanguageTag>>,

    id_token_hint: Option<String>,

    login_hint: Option<String>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    #[serde(default)]
    acr_values: Option<HashSet<String>>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct AuthorizationResponse {
    pub code: Option<String>,
    pub state: Option<String>,
    #[serde(flatten)]
    pub access_token: Option<AccessTokenResponse>,
}

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Bearer,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationCodeGrant {
    code: String,
    redirect_uri: Option<Url>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RefreshTokenGrant {
    refresh_token: String,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    scope: Option<HashSet<String>>,
}

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Display,
    FromStr,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum AccessTokenRequest {
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
    #[serde(skip_deserializing, other)]
    Unsupported,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AccessTokenResponse {
    access_token: String,

    token_type: TokenType,

    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    expires_in: Option<Duration>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    scope: Option<HashSet<String>>,
}

impl AccessTokenResponse {
    #[must_use]
    pub fn new(access_token: String) -> AccessTokenResponse {
        AccessTokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: None,
            scope: None,
        }
    }

    #[must_use]
    pub fn with_scopes(mut self, scope: HashSet<String>) -> Self {
        self.scope = Some(scope);
        self
    }

    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::json;

    use super::*;
    use crate::test_utils::assert_serde_json;

    #[test]
    fn serde_refresh_token_grant() {
        let expected = json!({
            "grant_type": "refresh_token",
            "refresh_token": "abcd",
            "scope": "openid",
        });

        let scope = {
            let mut s = HashSet::new();
            // TODO: insert multiple scopes and test it. It's a bit tricky to test since
            // HashSet have no guarantees regarding the ordering of items, so right
            // now the output is unstable.
            s.insert("openid".to_string());
            Some(s)
        };

        let req = AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token: "abcd".into(),
            scope,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn serde_authorization_code_grant() {
        let expected = json!({
            "grant_type": "authorization_code",
            "code": "abcd",
            "redirect_uri": "https://example.com/redirect",
        });

        let req = AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: "abcd".into(),
            redirect_uri: Some("https://example.com/redirect".parse().unwrap()),
        });

        assert_serde_json(&req, expected);
    }
}
