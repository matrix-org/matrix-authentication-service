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

use std::collections::HashSet;

use futures_util::future::Either;
use mas_iana::jose::{JsonWebKeyType, JsonWebKeyUse, JsonWebSignatureAlg};

use crate::JsonWebSignatureHeader;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Constraint<'a> {
    Alg {
        constraint_alg: JsonWebSignatureAlg,
    },

    Algs {
        constraint_algs: &'a [JsonWebSignatureAlg],
    },

    Kid {
        constraint_kid: &'a str,
    },

    Use {
        constraint_use: JsonWebKeyUse,
    },

    Kty {
        constraint_kty: JsonWebKeyType,
    },
}

impl<'a> Constraint<'a> {
    #[must_use]
    pub fn alg(constraint_alg: JsonWebSignatureAlg) -> Self {
        Constraint::Alg { constraint_alg }
    }

    #[must_use]
    pub fn algs(constraint_algs: &'a [JsonWebSignatureAlg]) -> Self {
        Constraint::Algs { constraint_algs }
    }

    #[must_use]
    pub fn kid(constraint_kid: &'a str) -> Self {
        Constraint::Kid { constraint_kid }
    }

    #[must_use]
    pub fn use_(constraint_use: JsonWebKeyUse) -> Self {
        Constraint::Use { constraint_use }
    }

    #[must_use]
    pub fn kty(constraint_kty: JsonWebKeyType) -> Self {
        Constraint::Kty { constraint_kty }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintDecision {
    Positive,
    Neutral,
    Negative,
}

pub trait Constrainable {
    /// List of available algorithms for this key
    fn algs(&self) -> Option<Vec<JsonWebSignatureAlg>> {
        None
    }

    /// Key ID (`kid`) of this key
    fn kid(&self) -> Option<&str> {
        None
    }

    /// Usage specified for this key
    fn use_(&self) -> Option<JsonWebKeyUse> {
        None
    }

    /// Key type (`kty`) of this key
    fn kty(&self) -> JsonWebKeyType;
}

impl<L, R> Constrainable for Either<L, R>
where
    L: Constrainable,
    R: Constrainable,
{
    fn algs(&self) -> Option<Vec<JsonWebSignatureAlg>> {
        match self {
            Either::Left(l) => l.algs(),
            Either::Right(r) => r.algs(),
        }
    }

    fn kid(&self) -> Option<&str> {
        match self {
            Either::Left(l) => l.kid(),
            Either::Right(r) => r.kid(),
        }
    }

    fn use_(&self) -> Option<JsonWebKeyUse> {
        match self {
            Either::Left(l) => l.use_(),
            Either::Right(r) => r.use_(),
        }
    }

    fn kty(&self) -> JsonWebKeyType {
        match self {
            Either::Left(l) => l.kty(),
            Either::Right(r) => r.kty(),
        }
    }
}

impl<'a> Constraint<'a> {
    fn decide<T: Constrainable>(&self, constrainable: &T) -> ConstraintDecision {
        match self {
            Constraint::Alg { constraint_alg } => {
                if let Some(algs) = constrainable.algs() {
                    if algs.contains(constraint_alg) {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Algs { constraint_algs } => {
                if let Some(algs) = constrainable.algs() {
                    if algs.iter().any(|alg| constraint_algs.contains(alg)) {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Kid { constraint_kid } => {
                if let Some(kid) = constrainable.kid() {
                    if kid == *constraint_kid {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Use { constraint_use } => {
                if let Some(use_) = constrainable.use_() {
                    if use_ == *constraint_use {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Kty { constraint_kty } => {
                if *constraint_kty == constrainable.kty() {
                    ConstraintDecision::Positive
                } else {
                    ConstraintDecision::Negative
                }
            }
        }
    }
}

#[derive(Default)]
pub struct ConstraintSet<'a> {
    constraints: HashSet<Constraint<'a>>,
}

impl<'a> FromIterator<Constraint<'a>> for ConstraintSet<'a> {
    fn from_iter<T: IntoIterator<Item = Constraint<'a>>>(iter: T) -> Self {
        Self {
            constraints: HashSet::from_iter(iter),
        }
    }
}

#[allow(dead_code)]
impl<'a> ConstraintSet<'a> {
    pub fn new(constraints: impl IntoIterator<Item = Constraint<'a>>) -> Self {
        constraints.into_iter().collect()
    }

    pub fn filter<'b, T: Constrainable, I: IntoIterator<Item = &'b T>>(
        &self,
        constrainables: I,
    ) -> Vec<&'b T> {
        let mut selected = Vec::new();

        'outer: for constrainable in constrainables {
            let mut score = 0;

            for constraint in &self.constraints {
                match constraint.decide(constrainable) {
                    ConstraintDecision::Positive => score += 1,
                    ConstraintDecision::Neutral => {}
                    // If any constraint was negative, don't add it to the candidates
                    ConstraintDecision::Negative => continue 'outer,
                }
            }

            selected.push((score, constrainable));
        }

        selected.sort_by_key(|(score, _)| *score);

        selected
            .into_iter()
            .map(|(_score, constrainable)| constrainable)
            .collect()
    }

    #[must_use]
    pub fn alg(mut self, constraint_alg: JsonWebSignatureAlg) -> Self {
        self.constraints.insert(Constraint::alg(constraint_alg));
        self
    }

    #[must_use]
    pub fn algs(mut self, constraint_algs: &'a [JsonWebSignatureAlg]) -> Self {
        self.constraints.insert(Constraint::algs(constraint_algs));
        self
    }

    #[must_use]
    pub fn kid(mut self, constraint_kid: &'a str) -> Self {
        self.constraints.insert(Constraint::kid(constraint_kid));
        self
    }

    #[must_use]
    pub fn use_(mut self, constraint_use: JsonWebKeyUse) -> Self {
        self.constraints.insert(Constraint::use_(constraint_use));
        self
    }

    #[must_use]
    pub fn kty(mut self, constraint_kty: JsonWebKeyType) -> Self {
        self.constraints.insert(Constraint::kty(constraint_kty));
        self
    }
}

impl<'a> From<&'a JsonWebSignatureHeader> for ConstraintSet<'a> {
    fn from(header: &'a JsonWebSignatureHeader) -> Self {
        let mut constraints = Self::default().alg(header.alg());

        if let Some(kid) = header.kid() {
            constraints = constraints.kid(kid);
        }

        constraints
    }
}
