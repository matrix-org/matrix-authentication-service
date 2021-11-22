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

use std::{borrow::Cow, collections::HashSet, iter::FromIterator, ops::Deref, str::FromStr};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[error("Invalid scope format")]
pub struct InvalidScope;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeToken(Cow<'static, str>);

impl ScopeToken {
    /// Create a `ScopeToken` from a static string. The validity of it is not
    /// checked since it has to be valid in const contexts
    #[must_use]
    pub const fn from_static(token: &'static str) -> Self {
        Self(Cow::Borrowed(token))
    }
}

pub const OPENID: ScopeToken = ScopeToken::from_static("openid");
pub const PROFILE: ScopeToken = ScopeToken::from_static("profile");
pub const EMAIL: ScopeToken = ScopeToken::from_static("email");
pub const ADDRESS: ScopeToken = ScopeToken::from_static("address");
pub const PHONE: ScopeToken = ScopeToken::from_static("phone");
pub const OFFLINE_ACCESS: ScopeToken = ScopeToken::from_static("offline_access");

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
            Ok(ScopeToken(Cow::Owned(s.into())))
        } else {
            Err(InvalidScope)
        }
    }
}

impl Deref for ScopeToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToString for ScopeToken {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(HashSet<ScopeToken>);

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

    #[must_use]
    pub fn contains(&self, token: &str) -> bool {
        ScopeToken::from_str(token)
            .map(|token| self.0.contains(&token))
            .unwrap_or(false)
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
        assert_eq!(ScopeToken::from_str("openid"), Ok(OPENID));

        assert_eq!(ScopeToken::from_str("invalid\\scope"), Err(InvalidScope));
    }

    #[test]
    fn parse_scope() {
        let scope = Scope::from_str("openid profile address").unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.contains("openid"));
        assert!(scope.contains("profile"));
        assert!(scope.contains("address"));
        assert!(!scope.contains("unknown"));

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
        assert!(scope.contains("openid"));
        assert!(!scope.contains("profile"));
        assert!(!scope.contains("address"));

        assert_eq!(
            Scope::from_str("order does not matter"),
            Scope::from_str("matter not order does"),
        );

        assert!(Scope::from_str("http://example.com").is_ok());
        assert!(Scope::from_str("urn:matrix:*").is_ok());
    }
}
