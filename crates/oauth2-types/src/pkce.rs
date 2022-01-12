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

use std::borrow::Cow;

use data_encoding::BASE64URL_NOPAD;
use mas_iana::oauth::PkceCodeChallengeMethod;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub trait CodeChallengeMethodExt {
    #[must_use]
    fn compute_challenge(self, verifier: &str) -> Cow<'_, str>;

    #[must_use]
    fn verify(self, challenge: &str, verifier: &str) -> bool;
}

impl CodeChallengeMethodExt for PkceCodeChallengeMethod {
    fn compute_challenge(self, verifier: &str) -> Cow<'_, str> {
        match self {
            Self::Plain => verifier.into(),
            Self::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                let verifier = BASE64URL_NOPAD.encode(&hash);
                verifier.into()
            }
        }
    }

    fn verify(self, challenge: &str, verifier: &str) -> bool {
        self.compute_challenge(verifier) == challenge
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub code_challenge_method: PkceCodeChallengeMethod,
    pub code_challenge: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    pub code_challenge_verifier: String,
}
