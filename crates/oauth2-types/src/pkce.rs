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
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeChallengeError {
    #[error("code_verifier should be at least 43 characters long")]
    TooShort,

    #[error("code_verifier should be at most 128 characters long")]
    TooLong,

    #[error("code_verifier contains invalid characters")]
    InvalidCharacters,

    #[error("challenge verification failed")]
    VerificationFailed,

    #[error("unknown challenge method")]
    UnknownChallengeMethod,
}

fn validate_verifier(verifier: &str) -> Result<(), CodeChallengeError> {
    if verifier.len() < 43 {
        return Err(CodeChallengeError::TooShort);
    }

    if verifier.len() > 128 {
        return Err(CodeChallengeError::TooLong);
    }

    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
    {
        return Err(CodeChallengeError::InvalidCharacters);
    }

    Ok(())
}

pub trait CodeChallengeMethodExt {
    /// Compute the challenge for a given verifier
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier did not adhere to the rules defined by
    /// the RFC in terms of length and allowed characters
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError>;

    /// Verify that a given verifier is valid for the given challenge
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier did not match the challenge, or if the
    /// verifier did not adhere to the rules defined by the RFC in terms of
    /// length and allowed characters
    fn verify(&self, challenge: &str, verifier: &str) -> Result<(), CodeChallengeError>
    where
        Self: Sized,
    {
        if self.compute_challenge(verifier)? == challenge {
            Ok(())
        } else {
            Err(CodeChallengeError::VerificationFailed)
        }
    }
}

impl CodeChallengeMethodExt for PkceCodeChallengeMethod {
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError> {
        validate_verifier(verifier)?;

        let challenge = match self {
            Self::Plain => verifier.into(),
            Self::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                let verifier = BASE64URL_NOPAD.encode(&hash);
                verifier.into()
            }
            _ => return Err(CodeChallengeError::UnknownChallengeMethod),
        };

        Ok(challenge)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_verification() {
        use PkceCodeChallengeMethod::{Plain, S256};
        // This challenge comes from the RFC7636 appendices
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(S256
            .verify(challenge, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .is_ok());

        assert!(Plain.verify(challenge, challenge).is_ok());

        assert_eq!(
            S256.verify(challenge, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Err(CodeChallengeError::VerificationFailed),
        );

        assert_eq!(
            S256.verify(challenge, "tooshort"),
            Err(CodeChallengeError::TooShort),
        );

        assert_eq!(
            S256.verify(challenge, "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong"),
            Err(CodeChallengeError::TooLong),
        );

        assert_eq!(
            S256.verify(
                challenge,
                "this is long enough but has invalid characters in it"
            ),
            Err(CodeChallengeError::InvalidCharacters),
        );
    }
}
