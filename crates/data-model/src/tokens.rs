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

use chrono::{DateTime, Utc};
use crc::{Crc, CRC_32_ISO_HDLC};
use mas_iana::oauth::OAuthTokenTypeHint;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use thiserror::Error;
use ulid::Ulid;

use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AccessTokenState {
    #[default]
    Valid,
    Revoked {
        revoked_at: DateTime<Utc>,
    },
}

impl AccessTokenState {
    fn revoke(self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Revoked { revoked_at }),
            Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the refresh token state is [`Valid`].
    ///
    /// [`Valid`]: AccessTokenState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the refresh token state is [`Revoked`].
    ///
    /// [`Revoked`]: AccessTokenState::Revoked
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub id: Ulid,
    pub state: AccessTokenState,
    pub session_id: Ulid,
    pub access_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    #[must_use]
    pub fn jti(&self) -> String {
        self.id.to_string()
    }

    /// Whether the access token is valid, i.e. not revoked and not expired
    ///
    /// # Parameters
    ///
    /// * `now` - The current time
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        self.state.is_valid() && !self.is_expired(now)
    }

    /// Whether the access token is expired
    ///
    /// Always returns `false` if the access token does not have an expiry time.
    ///
    /// # Parameters
    ///
    /// * `now` - The current time
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at < now,
            None => false,
        }
    }

    /// Mark the access token as revoked
    ///
    /// # Parameters
    ///
    /// * `revoked_at` - The time at which the access token was revoked
    ///
    /// # Errors
    ///
    /// Returns an error if the access token is already revoked
    pub fn revoke(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.revoke(revoked_at)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RefreshTokenState {
    #[default]
    Valid,
    Consumed {
        consumed_at: DateTime<Utc>,
    },
}

impl RefreshTokenState {
    fn consume(self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Consumed { consumed_at }),
            Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the refresh token state is [`Valid`].
    ///
    /// [`Valid`]: RefreshTokenState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the refresh token state is [`Consumed`].
    ///
    /// [`Consumed`]: RefreshTokenState::Consumed
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        matches!(self, Self::Consumed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: Ulid,
    pub state: RefreshTokenState,
    pub refresh_token: String,
    pub session_id: Ulid,
    pub created_at: DateTime<Utc>,
    pub access_token_id: Option<Ulid>,
}

impl std::ops::Deref for RefreshToken {
    type Target = RefreshTokenState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl RefreshToken {
    #[must_use]
    pub fn jti(&self) -> String {
        self.id.to_string()
    }

    pub fn consume(mut self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.consume(consumed_at)?;
        Ok(self)
    }
}

/// Type of token to generate or validate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// An access token, used by Relying Parties to authenticate requests
    AccessToken,

    /// A refresh token, used by the refresh token grant
    RefreshToken,

    /// A legacy access token
    CompatAccessToken,

    /// A legacy refresh token
    CompatRefreshToken,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::AccessToken => write!(f, "access token"),
            TokenType::RefreshToken => write!(f, "refresh token"),
            TokenType::CompatAccessToken => write!(f, "compat access token"),
            TokenType::CompatRefreshToken => write!(f, "compat refresh token"),
        }
    }
}

impl TokenType {
    fn prefix(self) -> &'static str {
        match self {
            TokenType::AccessToken => "mat",
            TokenType::RefreshToken => "mar",
            TokenType::CompatAccessToken => "mct",
            TokenType::CompatRefreshToken => "mcr",
        }
    }

    fn match_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "mat" => Some(TokenType::AccessToken),
            "mar" => Some(TokenType::RefreshToken),
            "mct" | "syt" => Some(TokenType::CompatAccessToken),
            "mcr" | "syr" => Some(TokenType::CompatRefreshToken),
            _ => None,
        }
    }

    /// Generate a token for the given type
    ///
    /// ```rust
    /// extern crate rand;
    ///
    /// use rand::thread_rng;
    /// use mas_data_model::TokenType::{AccessToken, RefreshToken};
    ///
    /// AccessToken.generate(&mut thread_rng());
    /// RefreshToken.generate(&mut thread_rng());
    /// ```
    pub fn generate(self, rng: &mut (impl RngCore + ?Sized)) -> String {
        let random_part: String = rng
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();

        let base = format!("{prefix}_{random_part}", prefix = self.prefix());
        let crc = CRC.checksum(base.as_bytes());
        let crc = base62_encode(crc);
        format!("{base}_{crc}")
    }

    /// Check the format of a token and determine its type
    ///
    /// ```rust
    /// use mas_data_model::TokenType;
    ///
    /// assert_eq!(
    ///     TokenType::check("mat_kkLSacJDpek22jKWw4AcXG68b7U3W6_0Lg9yb"),
    ///     Ok(TokenType::AccessToken)
    /// );
    ///
    /// assert_eq!(
    ///     TokenType::check("mar_PkpplxPkfjsqvtdfUlYR1Afg2TpaHF_GaTQd2"),
    ///     Ok(TokenType::RefreshToken)
    /// );
    ///
    /// assert_eq!(
    ///     TokenType::check("syt_PkpplxPkfjsqvtdfUlYR1Afg2TpaHF_GaTQd2"),
    ///     Ok(TokenType::CompatAccessToken)
    /// );
    /// ```
    pub fn check(token: &str) -> Result<TokenType, TokenFormatError> {
        // these are legacy tokens imported from Synapse
        // we don't do any validation on them and continue as is
        if token.starts_with("syt_") {
            return Ok(TokenType::CompatAccessToken);
        }
        if token.starts_with("syr_") {
            return Ok(TokenType::CompatRefreshToken);
        }

        let split: Vec<&str> = token.split('_').collect();
        let [prefix, random_part, crc]: [&str; 3] = split
            .try_into()
            .map_err(|_| TokenFormatError::InvalidFormat)?;

        if prefix.len() != 3 || random_part.len() != 30 || crc.len() != 6 {
            return Err(TokenFormatError::InvalidFormat);
        }

        let token_type =
            TokenType::match_prefix(prefix).ok_or_else(|| TokenFormatError::UnknownPrefix {
                prefix: prefix.to_owned(),
            })?;

        let base = format!("{prefix}_{random_part}", prefix = token_type.prefix());
        let expected_crc = CRC.checksum(base.as_bytes());
        let expected_crc = base62_encode(expected_crc);
        if crc != expected_crc {
            return Err(TokenFormatError::InvalidCrc {
                expected: expected_crc,
                got: crc.to_owned(),
            });
        }

        Ok(token_type)
    }
}

impl PartialEq<OAuthTokenTypeHint> for TokenType {
    fn eq(&self, other: &OAuthTokenTypeHint) -> bool {
        matches!(
            (self, other),
            (
                TokenType::AccessToken | TokenType::CompatAccessToken,
                OAuthTokenTypeHint::AccessToken
            ) | (
                TokenType::RefreshToken | TokenType::CompatRefreshToken,
                OAuthTokenTypeHint::RefreshToken
            )
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

    format!("{res:0>6}")
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Invalid token
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenFormatError {
    /// Overall token format is invalid
    #[error("invalid token format")]
    InvalidFormat,

    /// Token used an unknown prefix
    #[error("unknown token prefix {prefix:?}")]
    UnknownPrefix {
        /// The prefix found in the token
        prefix: String,
    },

    /// The CRC checksum in the token is invalid
    #[error("invalid crc {got:?}, expected {expected:?}")]
    InvalidCrc {
        /// The CRC hash expected to be found in the token
        expected: String,
        /// The CRC found in the token
        got: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_prefix_match() {
        use TokenType::{AccessToken, CompatAccessToken, CompatRefreshToken, RefreshToken};
        assert_eq!(TokenType::match_prefix("syt"), Some(CompatAccessToken));
        assert_eq!(TokenType::match_prefix("syr"), Some(CompatRefreshToken));
        assert_eq!(TokenType::match_prefix("mct"), Some(CompatAccessToken));
        assert_eq!(TokenType::match_prefix("mcr"), Some(CompatRefreshToken));
        assert_eq!(TokenType::match_prefix("mat"), Some(AccessToken));
        assert_eq!(TokenType::match_prefix("mar"), Some(RefreshToken));
        assert_eq!(TokenType::match_prefix("matt"), None);
        assert_eq!(TokenType::match_prefix("marr"), None);
        assert_eq!(TokenType::match_prefix("ma"), None);
        assert_eq!(
            TokenType::match_prefix(TokenType::CompatAccessToken.prefix()),
            Some(TokenType::CompatAccessToken)
        );
        assert_eq!(
            TokenType::match_prefix(TokenType::CompatRefreshToken.prefix()),
            Some(TokenType::CompatRefreshToken)
        );
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

        #[allow(clippy::disallowed_methods)]
        let mut rng = thread_rng();

        for t in [
            TokenType::CompatAccessToken,
            TokenType::CompatRefreshToken,
            TokenType::AccessToken,
            TokenType::RefreshToken,
        ] {
            // Generate many tokens
            let tokens: HashSet<String> = (0..COUNT).map(|_| t.generate(&mut rng)).collect();

            // Check that they are all different
            assert_eq!(tokens.len(), COUNT, "All tokens are unique");

            // Check that they are all valid and detected as the right token type
            for token in tokens {
                assert_eq!(TokenType::check(&token).unwrap(), t);
            }
        }
    }
}
