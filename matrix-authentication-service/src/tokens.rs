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

use std::convert::TryInto;

use crc::{Crc, CRC_32_ISO_HDLC};
use oauth2_types::requests::TokenTypeHint;
use rand::{distributions::Alphanumeric, Rng};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    AccessToken,
    RefreshToken,
}

impl TokenType {
    fn prefix(self) -> &'static str {
        match self {
            TokenType::AccessToken => "mat",
            TokenType::RefreshToken => "mar",
        }
    }

    fn match_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "mat" => Some(TokenType::AccessToken),
            "mar" => Some(TokenType::RefreshToken),
            _ => None,
        }
    }
}

impl PartialEq<TokenTypeHint> for TokenType {
    fn eq(&self, other: &TokenTypeHint) -> bool {
        matches!(
            (self, other),
            (TokenType::AccessToken, TokenTypeHint::AccessToken)
                | (TokenType::RefreshToken, TokenTypeHint::RefreshToken)
        )
    }
}

const NUM: [u8; 62] = *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(mut num: u32) -> String {
    let mut res = String::with_capacity(6);
    while num > 0 {
        res.push(NUM[(num % 62) as usize] as char);
        num /= 62;
    }

    format!("{:0>6}", res)
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

pub fn generate(rng: impl Rng, token_type: TokenType) -> String {
    let random_part: String = rng
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let base = format!("{}_{}", token_type.prefix(), random_part);
    let crc = CRC.checksum(base.as_bytes());
    let crc = base62_encode(crc);
    format!("{}_{}", base, crc)
}

#[derive(Debug, Error)]
pub enum TokenFormatError {
    #[error("invalid token format")]
    InvalidFormat,

    #[error("unknown token prefix {prefix:?}")]
    UnknownPrefix { prefix: String },

    #[error("invalid crc {got:?}, expected {expected:?}")]
    InvalidCrc { expected: String, got: String },
}

#[allow(dead_code)]
pub fn check(token: &str) -> Result<TokenType, TokenFormatError> {
    let split: Vec<&str> = token.split('_').collect();
    let [prefix, random_part, crc]: [&str; 3] = split
        .try_into()
        .map_err(|_| TokenFormatError::InvalidFormat)?;

    if prefix.len() != 3 || random_part.len() != 30 || crc.len() != 6 {
        return Err(TokenFormatError::InvalidFormat);
    }

    let token_type =
        TokenType::match_prefix(prefix).ok_or_else(|| TokenFormatError::UnknownPrefix {
            prefix: prefix.to_string(),
        })?;

    let base = format!("{}_{}", token_type.prefix(), random_part);
    let expected_crc = CRC.checksum(base.as_bytes());
    let expected_crc = base62_encode(expected_crc);
    if crc != expected_crc {
        return Err(TokenFormatError::InvalidCrc {
            expected: expected_crc,
            got: crc.to_string(),
        });
    }

    Ok(token_type)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_prefix_match() {
        use TokenType::{AccessToken, RefreshToken};
        assert_eq!(TokenType::match_prefix("mat"), Some(AccessToken));
        assert_eq!(TokenType::match_prefix("mar"), Some(RefreshToken));
        assert_eq!(TokenType::match_prefix("matt"), None);
        assert_eq!(TokenType::match_prefix("marr"), None);
        assert_eq!(TokenType::match_prefix("ma"), None);
        assert_eq!(
            TokenType::match_prefix(TokenType::AccessToken.prefix()),
            Some(TokenType::AccessToken)
        );
        assert_eq!(
            TokenType::match_prefix(TokenType::RefreshToken.prefix()),
            Some(TokenType::RefreshToken)
        );
    }

    #[test]
    fn test_generate_and_check() {
        const COUNT: usize = 500; // Generate 500 of each token type
        let mut rng = thread_rng();
        // Generate many access tokens
        let tokens: HashSet<String> = (0..COUNT)
            .map(|_| generate(&mut rng, TokenType::AccessToken))
            .collect();

        // Check that they are all different
        assert_eq!(tokens.len(), COUNT, "All tokens are unique");

        // Check that they are all valid and detected as access tokens
        for token in tokens {
            assert_eq!(check(&token).unwrap(), TokenType::AccessToken);
        }

        // Same, but for refresh tokens
        let tokens: HashSet<String> = (0..COUNT)
            .map(|_| generate(&mut rng, TokenType::RefreshToken))
            .collect();

        assert_eq!(tokens.len(), COUNT, "All tokens are unique");

        for token in tokens {
            assert_eq!(check(&token).unwrap(), TokenType::RefreshToken);
        }
    }
}
