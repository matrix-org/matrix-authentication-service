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

use std::{collections::HashSet, hash::Hash, time::Duration};

use language_tags::LanguageTag;
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{rust::StringWithSeparator, serde_as, DurationSeconds, SpaceSeparator};
use url::Url;

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Display, FromStr, Serialize)]
#[display(style = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Code,
    IdToken,
    Token,
    None,
}

#[derive(Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

#[derive(Serialize, Deserialize, FromStr)]
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
    response_type: HashSet<ResponseType>,

    client_id: String,

    redirect_uri: Option<Url>,

    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    scope: HashSet<String>,

    state: Option<String>,

    response_mode: Option<ResponseMode>,

    nonce: Option<String>,

    display: Option<Display>,

    #[serde_as(as = "Option<DurationSeconds>")]
    max_age: Option<Duration>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    ui_locales: Option<Vec<LanguageTag>>,

    id_token_hint: Option<String>,

    login_hint: Option<String>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    acr_values: Option<HashSet<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthorizationResponse {
    code: String,
    state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq)]
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

    #[serde_as(as = "Option<DurationSeconds>")]
    expires_in: Option<Duration>,

    refresh_token: Option<String>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    scope: Option<HashSet<String>>,
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
