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

use std::{collections::HashSet, hash::Hash, num::NonZeroU32};

use chrono::{DateTime, Duration, Utc};
use language_tags::LanguageTag;
use mas_iana::oauth::{
    OAuthAccessTokenType, OAuthAuthorizationEndpointResponseType, OAuthTokenTypeHint,
};
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use serde_with::{
    rust::StringWithSeparator, serde_as, skip_serializing_none, DisplayFromStr, DurationSeconds,
    SpaceSeparator, TimestampSeconds,
};
use url::Url;

use crate::scope::Scope;

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
    pub response_type: OAuthAuthorizationEndpointResponseType,

    pub client_id: String,

    pub redirect_uri: Option<Url>,

    pub scope: Scope,

    pub state: Option<String>,

    pub response_mode: Option<ResponseMode>,

    pub nonce: Option<String>,

    display: Option<Display>,

    pub prompt: Option<Prompt>,

    #[serde(default)]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub max_age: Option<NonZeroU32>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    ui_locales: Option<Vec<LanguageTag>>,

    id_token_hint: Option<String>,

    login_hint: Option<String>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    #[serde(default)]
    acr_values: Option<HashSet<String>>,

    pub request: Option<String>,

    pub request_uri: Option<Url>,

    pub registration: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct AuthorizationResponse<R> {
    pub code: Option<String>,
    #[serde(flatten)]
    pub response: R,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationCodeGrant {
    pub code: String,
    #[serde(default)]
    pub redirect_uri: Option<Url>,

    // TODO: move this somehow in the pkce module
    #[serde(default)]
    pub code_verifier: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RefreshTokenGrant {
    pub refresh_token: String,

    #[serde(default)]
    scope: Option<Scope>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ClientCredentialsGrant {
    #[serde(default)]
    scope: Option<Scope>,
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
    ClientCredentials,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum AccessTokenRequest {
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
    ClientCredentials(ClientCredentialsGrant),
    #[serde(skip_deserializing, other)]
    Unsupported,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AccessTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    // TODO: this should be somewhere else
    id_token: Option<String>,

    token_type: OAuthAccessTokenType,

    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    expires_in: Option<Duration>,

    scope: Option<Scope>,
}

impl AccessTokenResponse {
    #[must_use]
    pub fn new(access_token: String) -> AccessTokenResponse {
        AccessTokenResponse {
            access_token,
            refresh_token: None,
            id_token: None,
            token_type: OAuthAccessTokenType::Bearer,
            expires_in: None,
            scope: None,
        }
    }

    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    #[must_use]
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IntrospectionRequest {
    pub token: String,

    #[serde(default)]
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct IntrospectionResponse {
    pub active: bool,

    pub scope: Option<Scope>,

    pub client_id: Option<String>,

    pub username: Option<String>,

    pub token_type: Option<OAuthTokenTypeHint>,

    #[serde_as(as = "Option<TimestampSeconds>")]
    pub exp: Option<DateTime<Utc>>,

    #[serde_as(as = "Option<TimestampSeconds>")]
    pub iat: Option<DateTime<Utc>>,

    #[serde_as(as = "Option<TimestampSeconds>")]
    pub nbf: Option<DateTime<Utc>>,

    pub sub: Option<String>,

    pub aud: Option<String>,

    pub iss: Option<String>,

    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{scope::OPENID, test_utils::assert_serde_json};

    #[test]
    fn serde_refresh_token_grant() {
        let expected = json!({
            "grant_type": "refresh_token",
            "refresh_token": "abcd",
            "scope": "openid",
        });

        // TODO: insert multiple scopes and test it. It's a bit tricky to test since
        // HashSet have no guarantees regarding the ordering of items, so right
        // now the output is unstable.
        let scope: Option<Scope> = Some(vec![OPENID].into_iter().collect());

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
            code_verifier: None,
        });

        assert_serde_json(&req, expected);
    }
}
