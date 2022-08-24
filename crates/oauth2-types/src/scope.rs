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

#![allow(clippy::module_name_repetitions)]

use std::{collections::HashSet, fmt, iter::FromIterator, str::FromStr};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[error("Invalid scope format")]
pub struct InvalidScope;

/// Tokens to define the scope of an access token or to request specific claims.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub enum ScopeToken {
    /// `openid`
    ///
    /// Required for OpenID Connect requests.
    Openid,

    /// `profile`
    ///
    /// Requests access to the end-user's profile.
    Profile,

    /// `email`
    ///
    /// Requests access to the end-user's email address.
    Email,

    /// `address`
    ///
    /// Requests access to the end-user's address.
    Address,

    /// `phone`
    ///
    /// Requests access to the end-user's phone number.
    Phone,

    /// `offline_access`
    ///
    /// Requests that an OAuth 2.0 refresh token be issued that can be used to
    /// obtain an access token that grants access to the end-user's UserInfo
    /// Endpoint even when the end-user is not present (not logged in).
    OfflineAccess,

    /// `urn:matrix:org.matrix.msc2967.client:api:*`
    ///
    /// Requests access to the Matrix Client API.
    MatrixApi,

    /// `urn:matrix:org.matrix.msc2967.client:device:{device_id}`
    ///
    /// Requests access to the Matrix device with the given `device_id`.
    MatrixDevice(String),

    /// Another scope token.
    Custom(String),
}

impl fmt::Display for ScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeToken::Openid => write!(f, "openid"),
            ScopeToken::Profile => write!(f, "profile"),
            ScopeToken::Email => write!(f, "email"),
            ScopeToken::Address => write!(f, "address"),
            ScopeToken::Phone => write!(f, "phone"),
            ScopeToken::OfflineAccess => write!(f, "offline_access"),
            ScopeToken::MatrixApi => write!(f, "urn:matrix:org.matrix.msc2967.client:api:*"),
            ScopeToken::MatrixDevice(s) => {
                write!(f, "urn:matrix:org.matrix.msc2967.client:device:{s}")
            }
            ScopeToken::Custom(s) => f.write_str(s),
        }
    }
}

// As per RFC6749 appendix A:
// https://datatracker.ietf.org/doc/html/rfc6749#appendix-A
//
//    NQCHAR     = %x21 / %x23-5B / %x5D-7E
fn nqchar(c: char) -> bool {
    '\x21' == c || ('\x23'..'\x5B').contains(&c) || ('\x5D'..'\x7E').contains(&c)
}

impl FromStr for ScopeToken {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // As per RFC6749 appendix A.4:
        // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
        //
        //    scope-token = 1*NQCHAR
        if !s.is_empty() && s.chars().all(nqchar) {
            let token = match s {
                "openid" => Self::Openid,
                "profile" => Self::Profile,
                "email" => Self::Email,
                "address" => Self::Address,
                "phone" => Self::Phone,
                "offline_access" => Self::OfflineAccess,
                "urn:matrix:org.matrix.msc2967.client:api:*" => Self::MatrixApi,
                _ => {
                    if let Some(device_id) =
                        s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:")
                    {
                        Self::MatrixDevice(device_id.to_owned())
                    } else {
                        Self::Custom(s.to_owned())
                    }
                }
            };
            Ok(token)
        } else {
            Err(InvalidScope)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(HashSet<ScopeToken>);

impl std::ops::Deref for Scope {
    type Target = HashSet<ScopeToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Scope {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // As per RFC6749 appendix A.4:
        // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
        //
        //    scope       = scope-token *( SP scope-token )
        let scopes: Result<HashSet<ScopeToken>, InvalidScope> =
            s.split(' ').map(ScopeToken::from_str).collect();

        Ok(Self(scopes?))
    }
}

impl Scope {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // This should never be the case?
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn insert(&mut self, value: ScopeToken) -> bool {
        self.0.insert(value)
    }
}

impl ToString for Scope {
    fn to_string(&self) -> String {
        let it = self.0.iter().map(ScopeToken::to_string);
        Itertools::intersperse(it, ' '.to_string()).collect()
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // FIXME: seems like there is an unnecessary clone here?
        let scope: String = Deserialize::deserialize(deserializer)?;
        Scope::from_str(&scope).map_err(serde::de::Error::custom)
    }
}

impl FromIterator<ScopeToken> for Scope {
    fn from_iter<T: IntoIterator<Item = ScopeToken>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_token() {
        assert_eq!(ScopeToken::from_str("openid"), Ok(ScopeToken::Openid));

        assert_eq!(ScopeToken::from_str("invalid\\scope"), Err(InvalidScope));
    }

    #[test]
    fn parse_scope() {
        let scope = Scope::from_str("openid profile address").unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.contains(&ScopeToken::Openid));
        assert!(scope.contains(&ScopeToken::Profile));
        assert!(scope.contains(&ScopeToken::Address));
        assert!(!scope.contains(&ScopeToken::OfflineAccess));

        assert!(
            Scope::from_str("").is_err(),
            "there should always be at least one token in the scope"
        );

        assert!(Scope::from_str("invalid\\scope").is_err());
        assert!(Scope::from_str("no  double space").is_err());
        assert!(Scope::from_str(" no leading space").is_err());
        assert!(Scope::from_str("no trailing space ").is_err());

        let scope = Scope::from_str("openid").unwrap();
        assert_eq!(scope.len(), 1);
        assert!(scope.contains(&ScopeToken::Openid));
        assert!(!scope.contains(&ScopeToken::Profile));
        assert!(!scope.contains(&ScopeToken::Address));

        assert_eq!(
            Scope::from_str("order does not matter"),
            Scope::from_str("matter not order does"),
        );

        assert!(Scope::from_str("http://example.com").is_ok());
        assert!(Scope::from_str("urn:matrix:org.matrix.msc2967.client:*").is_ok());

        let device_id = "ABCDEFGHIJKL".to_owned();
        let scope =
            Scope::from_str("urn:matrix:org.matrix.msc2967.client:device:ABCDEFGHIJKL").unwrap();
        let mut scope_iter = scope.iter();
        assert_eq!(
            scope_iter.next(),
            Some(&ScopeToken::MatrixDevice(device_id))
        );
        assert_eq!(scope_iter.next(), None);
    }
}
