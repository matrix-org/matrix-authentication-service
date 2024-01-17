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

use mas_iana::jose::JsonWebSignatureAlg;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::{base64::Base64UrlNoPad, jwk::PublicJsonWebKey, Base64};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JsonWebSignatureHeader {
    alg: JsonWebSignatureAlg,

    #[serde(default)]
    jku: Option<Url>,

    #[serde(default)]
    jwk: Option<Box<PublicJsonWebKey>>,

    #[serde(default)]
    kid: Option<String>,

    #[serde(default)]
    x5u: Option<Url>,

    #[serde(default)]
    x5c: Option<Vec<Base64>>,

    #[serde(default)]
    x5t: Option<Base64UrlNoPad>,

    #[serde(default, rename = "x5t#S256")]
    x5t_s256: Option<Base64UrlNoPad>,

    #[serde(default)]
    typ: Option<String>,

    #[serde(default)]
    cty: Option<String>,

    #[serde(default)]
    crit: Option<Vec<String>>,
}

impl JsonWebSignatureHeader {
    #[must_use]
    pub fn new(alg: JsonWebSignatureAlg) -> Self {
        Self {
            alg,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            typ: None,
            cty: None,
            crit: None,
        }
    }

    #[must_use]
    pub const fn alg(&self) -> &JsonWebSignatureAlg {
        &self.alg
    }

    #[must_use]
    pub const fn jku(&self) -> Option<&Url> {
        self.jku.as_ref()
    }

    #[must_use]
    pub fn with_jku(mut self, jku: Url) -> Self {
        self.jku = Some(jku);
        self
    }

    #[must_use]
    pub const fn jwk(&self) -> Option<&PublicJsonWebKey> {
        // Can't use as_deref because it's not a const fn
        match &self.jwk {
            Some(jwk) => Some(jwk),
            None => None,
        }
    }

    #[must_use]
    pub fn with_jwk(mut self, jwk: PublicJsonWebKey) -> Self {
        self.jwk = Some(Box::new(jwk));
        self
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    #[must_use]
    pub fn with_typ(mut self, typ: String) -> Self {
        self.typ = Some(typ);
        self
    }

    #[must_use]
    pub fn crit(&self) -> Option<&[String]> {
        self.crit.as_deref()
    }

    #[must_use]
    pub fn with_crit(mut self, crit: Vec<String>) -> Self {
        self.crit = Some(crit);
        self
    }
}
