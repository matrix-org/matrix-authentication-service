// Copyright 2022 The Matrix.org Foundation C.I.C.
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

#![allow(clippy::module_name_repetitions)]

use std::{collections::BTreeSet, fmt, iter::FromIterator, str::FromStr};

use itertools::Itertools;
use mas_iana::oauth::OAuthAuthorizationEndpointResponseType;
use parse_display::{Display, FromStr};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

/// An error encountered when trying to parse an invalid [`ResponseType`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid response type")]
pub struct InvalidResponseType;

/// The accepted tokens in a [`ResponseType`].
///
/// `none` is not in this enum because it is represented by an empty
/// [`ResponseType`].
///
/// This type also accepts unknown tokens that can be constructed via it's
/// `FromStr` implementation or used via its `Display` implementation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    FromStr,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[display(style = "snake_case")]
#[non_exhaustive]
pub enum ResponseTypeToken {
    /// `code`
    Code,

    /// `id_token`
    IdToken,

    /// `token`
    Token,

    /// Unknown token.
    #[display("{0}")]
    Unknown(String),
}

/// An [OAuth 2.0 `response_type` value] that the client can use
/// at the [authorization endpoint].
///
/// It is recommended to construct this type from an
/// [`OAuthAuthorizationEndpointResponseType`].
///
/// [OAuth 2.0 `response_type` value]: https://www.rfc-editor.org/rfc/rfc7591#page-9
/// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[derive(Debug, Clone, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub struct ResponseType(BTreeSet<ResponseTypeToken>);

impl std::ops::Deref for ResponseType {
    type Target = BTreeSet<ResponseTypeToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ResponseType {
    /// Whether this response type requests a code.
    #[must_use]
    pub fn has_code(&self) -> bool {
        self.0.contains(&ResponseTypeToken::Code)
    }

    /// Whether this response type requests an ID token.
    #[must_use]
    pub fn has_id_token(&self) -> bool {
        self.0.contains(&ResponseTypeToken::IdToken)
    }

    /// Whether this response type requests a token.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.0.contains(&ResponseTypeToken::Token)
    }
}

impl FromStr for ResponseType {
    type Err = InvalidResponseType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            Err(InvalidResponseType)
        } else if s == "none" {
            Ok(Self(BTreeSet::new()))
        } else {
            s.split_ascii_whitespace()
                .map(|t| ResponseTypeToken::from_str(t).or(Err(InvalidResponseType)))
                .collect::<Result<_, _>>()
        }
    }
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let res = Itertools::intersperse(self.iter().map(ToString::to_string), ' '.to_string())
            .collect::<String>();

        if res.is_empty() {
            write!(f, "none")
        } else {
            f.write_str(&res)
        }
    }
}

impl FromIterator<ResponseTypeToken> for ResponseType {
    fn from_iter<T: IntoIterator<Item = ResponseTypeToken>>(iter: T) -> Self {
        Self(BTreeSet::from_iter(iter))
    }
}

impl From<OAuthAuthorizationEndpointResponseType> for ResponseType {
    fn from(response_type: OAuthAuthorizationEndpointResponseType) -> Self {
        match response_type {
            OAuthAuthorizationEndpointResponseType::Code => Self([ResponseTypeToken::Code].into()),
            OAuthAuthorizationEndpointResponseType::CodeIdToken => {
                Self([ResponseTypeToken::Code, ResponseTypeToken::IdToken].into())
            }
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken => Self(
                [
                    ResponseTypeToken::Code,
                    ResponseTypeToken::IdToken,
                    ResponseTypeToken::Token,
                ]
                .into(),
            ),
            OAuthAuthorizationEndpointResponseType::CodeToken => {
                Self([ResponseTypeToken::Code, ResponseTypeToken::Token].into())
            }
            OAuthAuthorizationEndpointResponseType::IdToken => {
                Self([ResponseTypeToken::IdToken].into())
            }
            OAuthAuthorizationEndpointResponseType::IdTokenToken => {
                Self([ResponseTypeToken::IdToken, ResponseTypeToken::Token].into())
            }
            OAuthAuthorizationEndpointResponseType::None => Self(BTreeSet::new()),
            OAuthAuthorizationEndpointResponseType::Token => {
                Self([ResponseTypeToken::Token].into())
            }
        }
    }
}

impl TryFrom<ResponseType> for OAuthAuthorizationEndpointResponseType {
    type Error = InvalidResponseType;

    fn try_from(response_type: ResponseType) -> Result<Self, Self::Error> {
        if response_type
            .iter()
            .any(|t| matches!(t, ResponseTypeToken::Unknown(_)))
        {
            return Err(InvalidResponseType);
        }

        let tokens = response_type.iter().collect::<Vec<_>>();
        let res = match *tokens {
            [ResponseTypeToken::Code] => OAuthAuthorizationEndpointResponseType::Code,
            [ResponseTypeToken::IdToken] => OAuthAuthorizationEndpointResponseType::IdToken,
            [ResponseTypeToken::Token] => OAuthAuthorizationEndpointResponseType::Token,
            [ResponseTypeToken::Code, ResponseTypeToken::IdToken] => {
                OAuthAuthorizationEndpointResponseType::CodeIdToken
            }
            [ResponseTypeToken::Code, ResponseTypeToken::Token] => {
                OAuthAuthorizationEndpointResponseType::CodeToken
            }
            [ResponseTypeToken::IdToken, ResponseTypeToken::Token] => {
                OAuthAuthorizationEndpointResponseType::IdTokenToken
            }
            [ResponseTypeToken::Code, ResponseTypeToken::IdToken, ResponseTypeToken::Token] => {
                OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
            }
            _ => OAuthAuthorizationEndpointResponseType::None,
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_response_type_token() {
        assert_eq!(
            serde_json::from_str::<ResponseTypeToken>("\"code\"").unwrap(),
            ResponseTypeToken::Code
        );
        assert_eq!(
            serde_json::from_str::<ResponseTypeToken>("\"id_token\"").unwrap(),
            ResponseTypeToken::IdToken
        );
        assert_eq!(
            serde_json::from_str::<ResponseTypeToken>("\"token\"").unwrap(),
            ResponseTypeToken::Token
        );
        assert_eq!(
            serde_json::from_str::<ResponseTypeToken>("\"something_unsupported\"").unwrap(),
            ResponseTypeToken::Unknown("something_unsupported".to_owned())
        );
    }

    #[test]
    fn serialize_response_type_token() {
        assert_eq!(
            serde_json::to_string(&ResponseTypeToken::Code).unwrap(),
            "\"code\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseTypeToken::IdToken).unwrap(),
            "\"id_token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseTypeToken::Token).unwrap(),
            "\"token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseTypeToken::Unknown(
                "something_unsupported".to_owned()
            ))
            .unwrap(),
            "\"something_unsupported\""
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deserialize_response_type() {
        serde_json::from_str::<ResponseType>("\"\"").unwrap_err();

        let res_type = serde_json::from_str::<ResponseType>("\"none\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::None
        );

        let res_type = serde_json::from_str::<ResponseType>("\"code\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::Code
        );

        let res_type = serde_json::from_str::<ResponseType>("\"code\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::Code
        );

        let res_type = serde_json::from_str::<ResponseType>("\"id_token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::IdToken
        );

        let res_type = serde_json::from_str::<ResponseType>("\"token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::Token
        );

        let res_type = serde_json::from_str::<ResponseType>("\"something_unsupported\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(
            iter.next(),
            Some(&ResponseTypeToken::Unknown(
                "something_unsupported".to_owned()
            ))
        );
        assert_eq!(iter.next(), None);
        OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap_err();

        let res_type = serde_json::from_str::<ResponseType>("\"code id_token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeIdToken
        );

        let res_type = serde_json::from_str::<ResponseType>("\"code token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeToken
        );

        let res_type = serde_json::from_str::<ResponseType>("\"id_token token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::IdTokenToken
        );

        let res_type = serde_json::from_str::<ResponseType>("\"code id_token token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
        );

        let res_type =
            serde_json::from_str::<ResponseType>("\"code id_token token something_unsupported\"")
                .unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(
            iter.next(),
            Some(&ResponseTypeToken::Unknown(
                "something_unsupported".to_owned()
            ))
        );
        assert_eq!(iter.next(), None);
        OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap_err();

        // Order doesn't matter
        let res_type = serde_json::from_str::<ResponseType>("\"token code id_token\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
        );

        let res_type =
            serde_json::from_str::<ResponseType>("\"id_token token id_token code\"").unwrap();
        let mut iter = res_type.iter();
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Code));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::IdToken));
        assert_eq!(iter.next(), Some(&ResponseTypeToken::Token));
        assert_eq!(iter.next(), None);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(res_type).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
        );
    }

    #[test]
    fn serialize_response_type() {
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::None
            ))
            .unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::Code
            ))
            .unwrap(),
            "\"code\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::IdToken
            ))
            .unwrap(),
            "\"id_token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::CodeIdToken
            ))
            .unwrap(),
            "\"code id_token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::CodeToken
            ))
            .unwrap(),
            "\"code token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::IdTokenToken
            ))
            .unwrap(),
            "\"id_token token\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseType::from(
                OAuthAuthorizationEndpointResponseType::CodeIdTokenToken
            ))
            .unwrap(),
            "\"code id_token token\""
        );

        assert_eq!(
            serde_json::to_string(
                &[
                    ResponseTypeToken::Unknown("something_unsupported".to_owned()),
                    ResponseTypeToken::Code
                ]
                .into_iter()
                .collect::<ResponseType>()
            )
            .unwrap(),
            "\"code something_unsupported\""
        );

        // Order doesn't matter.
        let res = [
            ResponseTypeToken::IdToken,
            ResponseTypeToken::Token,
            ResponseTypeToken::Code,
        ]
        .into_iter()
        .collect::<ResponseType>();
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            "\"code id_token token\""
        );

        let res = [
            ResponseTypeToken::Code,
            ResponseTypeToken::Token,
            ResponseTypeToken::IdToken,
        ]
        .into_iter()
        .collect::<ResponseType>();
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            "\"code id_token token\""
        );
    }
}
