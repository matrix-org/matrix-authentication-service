use std::hash::Hash;

use language_tags::LanguageTag;
use parse_display::{Display, FromStr};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::types::{Seconds, StringHashSet, StringVec};

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Display, FromStr)]
#[display(style = "snake_case")]
pub enum ResponseType {
    Code,
    IdToken,
    Token,
    None,
}

#[derive(Serialize, Deserialize)]
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
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

#[derive(Serialize, Deserialize)]
pub struct AuthorizationRequest {
    response_type: StringHashSet<ResponseType>,
    client_id: String,
    redirect_uri: Option<Url>,
    scope: StringHashSet<String>,
    state: Option<String>,
    response_mode: Option<ResponseMode>,
    nonce: Option<String>,
    display: Option<Display>,
    max_age: Option<Seconds>,
    ui_locales: Option<StringVec<LanguageTag>>,
    id_token_hint: Option<String>,
    login_hint: Option<String>,
    acr_values: Option<StringHashSet<String>>,
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RefreshTokenGrant {
    refresh_token: String,
    scope: Option<StringHashSet<String>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum AccessTokenRequest {
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
    #[serde(skip_deserializing, other)]
    Unsupported,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AccessTokenResponse {
    access_token: String,
    token_type: TokenType,
    expires_in: Option<Seconds>,
    refresh_token: Option<String>,
    scope: Option<StringHashSet<String>>,
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
            "scope": "openid profile",
        });

        let scope = {
            let mut s = HashSet::new();
            s.insert("openid".to_string());
            s.insert("profile".to_string());
            Some(s.into())
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
